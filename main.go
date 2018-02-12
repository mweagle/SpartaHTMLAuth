package main

import (
	"context"
	"fmt"
	"net/http"

	lambdaContext "github.com/aws/aws-lambda-go/lambdacontext"
	sparta "github.com/mweagle/Sparta"
	spartaCF "github.com/mweagle/Sparta/aws/cloudformation"
	spartaAWSEvents "github.com/mweagle/Sparta/aws/events"
	gocf "github.com/mweagle/go-cloudformation"
	"github.com/sirupsen/logrus"
)

func authLambdaRole() *gocf.IAMRole {
	return &gocf.IAMRole{
		AssumeRolePolicyDocument: gocf.IAMPolicyDocument{
			Version: "2012-10-17",
			Statement: []gocf.IAMPolicyStatement{
				gocf.IAMPolicyStatement{
					Effect: "Allow",
					Principal: &gocf.IAMPrincipal{
						Service: gocf.StringList(
							gocf.String(sparta.LambdaPrincipal),
						),
					},
					Action: gocf.StringList(
						gocf.String("sts:AssumeRole"),
					),
				},
			},
		},
		ManagedPolicyArns: gocf.StringList(
			gocf.String("arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"),
		),
	}
}

type authorizationResponse struct {
	PrincipalID    string                 `json:"principalId"`
	PolicyDocument gocf.IAMPolicyDocument `json:"policyDocument"`
	Context        map[string]interface{} `json:"context"`
}

func helloWorldAuthorizer(ctx context.Context,
	request map[string]interface{}) (interface{}, error) {

	awsContext, _ := lambdaContext.FromContext(ctx)
	logger, loggerOk := ctx.Value(sparta.ContextKeyLogger).(*logrus.Logger)
	if loggerOk {
		logger.Info("Hello world structured log message")
	}
	logger.WithFields(logrus.Fields{
		"ctx":   awsContext,
		"Event": request,
	}).Info("Checking current API Gateway stage status")
	methodArn, _ := request["methodArn"].(string)

	authResponse := &authorizationResponse{
		PrincipalID: "user",
		PolicyDocument: gocf.IAMPolicyDocument{
			Version: "2012-10-17",
			Statement: []gocf.IAMPolicyStatement{
				gocf.IAMPolicyStatement{
					Action: gocf.StringList(
						gocf.String("execute-api:Invoke"),
					),
					Effect: "Allow",
					Resource: gocf.StringList(
						gocf.String(methodArn),
					),
				},
			},
		},
		Context: map[string]interface{}{
			"Some": "Key",
		},
	}
	return authResponse, nil
}

////////////////////////////////////////////////////////////////////////////////
// Hello world event handler
type helloWorldResponse struct {
	Message string
	Request spartaAWSEvents.APIGatewayRequest
}

func helloWorld(ctx context.Context,
	gatewayEvent spartaAWSEvents.APIGatewayRequest) (interface{}, error) {
	/*
		 To return an error back to the client using a standard HTTP status code:

			errorResponse := spartaAPIG.NewErrorResponse(http.StatusInternalError,
			"Something failed inside here")
			return errorResponse, nil

			You can also create custom error response types, so long as they
			include `"code":HTTP_STATUS_CODE` somewhere in the response body.
			This reserved expression is what Sparta uses as a RegExp to determine
			the Integration Mapping value
	*/

	logger, loggerOk := ctx.Value(sparta.ContextKeyLogger).(*logrus.Logger)
	if loggerOk {
		logger.Info("Hello world structured log message")
	}

	// Return a message, together with the incoming input...
	return &helloWorldResponse{
		Message: fmt.Sprintf("Hello world 🌏"),
		Request: gatewayEvent,
	}, nil
}

func spartaHTMLLambdaFunctions(api *sparta.API) []*sparta.LambdaAWSInfo {

	lambdaAuthFunction := sparta.LambdaName(helloWorldAuthorizer)
	lambdaAuthRole := sparta.CloudFormationResourceName("AuthRole", "AuthRole")

	var lambdaFunctions []*sparta.LambdaAWSInfo
	lambdaFn := sparta.HandleAWSLambda(sparta.LambdaName(helloWorld),
		helloWorld,
		sparta.IAMRoleDefinition{})
	lambdaAuthFn := sparta.HandleAWSLambda(lambdaAuthFunction,
		helloWorldAuthorizer,
		sparta.IAMRoleDefinition{})

	if nil != api {
		apiGatewayResource, _ := api.NewResource("/hello", lambdaFn)

		// We only return http.StatusOK
		apiMethod, apiMethodErr := apiGatewayResource.NewMethod("GET",
			http.StatusOK,
			http.StatusInternalServerError)
		if nil != apiMethodErr {
			panic("Failed to create /hello resource: " + apiMethodErr.Error())
		}
		apiMethod.Parameters["method.request.header.Authorization"] = true
		// The lambda resource only supports application/json Unmarshallable
		// requests.
		apiMethod.SupportedRequestContentTypes = []string{"application/json"}
	}
	// Create the custom authorizer, just don't register it...
	authDecorator := func(serviceName string,
		lambdaResourceName string,
		lambdaResource gocf.LambdaFunction,
		resourceMetadata map[string]interface{},
		S3Bucket string,
		S3Key string,
		buildID string,
		template *gocf.Template,
		context map[string]interface{},
		logger *logrus.Logger) error {

		template.AddResource("CustomAuthorizer",
			&gocf.APIGatewayAuthorizer{
				Name: gocf.String("CustomAuthorizer"),
				Type: gocf.String("TOKEN"),
				AuthorizerResultTTLInSeconds: gocf.Integer(300),
				IDentitySource:               gocf.String("method.request.header.Authorization"),
				RestAPIID:                    gocf.Ref(api.LogicalResourceName()).String(),
				AuthorizerURI: gocf.Join("",
					gocf.String("arn:aws:apigateway:"),
					gocf.Ref("AWS::Region").String(),
					gocf.String(":lambda:path/2015-03-31/functions/"),
					gocf.GetAtt(lambdaAuthFn.LogicalResourceName(), "Arn"),
					gocf.String("/invocations")),
			})
		// AuthRole
		template.AddResource(lambdaAuthRole,
			authLambdaRole())
		// API Gateway permission
		perm := &gocf.LambdaPermission{
			Action:       gocf.String("lambda:InvokeFunction"),
			FunctionName: gocf.GetAtt(lambdaAuthFn.LogicalResourceName(), "Arn"),
			Principal:    gocf.String(sparta.APIGatewayPrincipal),
		}
		template.AddResource("APIGatewayAuthPerm", perm)
		return nil
	}
	lambdaAuthFn.Decorators = append(lambdaAuthFn.Decorators,
		sparta.TemplateDecoratorHookFunc(authDecorator))

	return append(lambdaFunctions, lambdaFn, lambdaAuthFn)
}

////////////////////////////////////////////////////////////////////////////////
// Main
func main() {
	// Provision an S3 site
	s3Site, s3SiteErr := sparta.NewS3Site("./resources")
	if s3SiteErr != nil {
		panic("Failed to create S3 Site")
	}

	// Register the function with the API Gateway
	apiStage := sparta.NewStage("v1")
	apiGateway := sparta.NewAPIGateway("SpartaHTMLAuth", apiStage)
	// Enable CORS s.t. the S3 site can access the resources
	apiGateway.CORSOptions = &sparta.CORSOptions{
		Headers: map[string]interface{}{
			"Access-Control-Allow-Headers": "Content-Type,X-Amz-Date,Authorization,X-Api-Key",
			"Access-Control-Allow-Methods": "*",
			"Access-Control-Allow-Origin":  gocf.GetAtt(s3Site.CloudFormationS3ResourceName(), "WebsiteURL"),
		},
	}

	// Deploy it
	stackName := spartaCF.UserScopedStackName("SpartaHTMLAuth")
	sparta.Main(stackName,
		fmt.Sprintf("SpartaHTML provisions a static S3 hosted website with an API Gateway resource backed by a custom Lambda function"),
		spartaHTMLLambdaFunctions(apiGateway),
		apiGateway,
		s3Site)
}
