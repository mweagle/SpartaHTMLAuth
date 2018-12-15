package main

import (
	"context"
	"fmt"
	"net/http"

	lambdaContext "github.com/aws/aws-lambda-go/lambdacontext"
	sparta "github.com/mweagle/Sparta"
	spartaAPIGateway "github.com/mweagle/Sparta/aws/apigateway"
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

	// Get the ARN and the Authorization Token
	methodArn, _ := request["methodArn"].(string)
	authToken, _ := request["authorizationToken"].(string)
	effect := "Deny"
	if authToken == "Sparta" {
		effect = "Allow"
	}
	authResponse := &authorizationResponse{
		PrincipalID: "user",
		PolicyDocument: gocf.IAMPolicyDocument{
			Version: "2012-10-17",
			Statement: []gocf.IAMPolicyStatement{
				gocf.IAMPolicyStatement{
					Action: gocf.StringList(
						gocf.String("execute-api:Invoke"),
					),
					Effect: effect,
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
	gatewayEvent spartaAWSEvents.APIGatewayRequest) (*spartaAPIGateway.Response, error) {
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
	return spartaAPIGateway.NewResponse(http.StatusOK, &helloWorldResponse{
		Message: fmt.Sprintf("Hello world 🌏"),
		Request: gatewayEvent,
	}), nil
}

func spartaHTMLLambdaFunctions(api *sparta.API) []*sparta.LambdaAWSInfo {
	lambbaCustomAuthorizer := sparta.CloudFormationResourceName("CustomAuth",
		"CustomAuth")
	lambdaAuthFunction := sparta.LambdaName(helloWorldAuthorizer)
	lambdaAuthRole := sparta.CloudFormationResourceName("AuthRole", "AuthRole")

	var lambdaFunctions []*sparta.LambdaAWSInfo
	lambdaFn, _ := sparta.NewAWSLambda(sparta.LambdaName(helloWorld),
		helloWorld,
		sparta.IAMRoleDefinition{})

	lambdaAuthFn, _ := sparta.NewAWSLambda(lambdaAuthFunction,
		helloWorldAuthorizer,
		sparta.IAMRoleDefinition{})

	lambdaFn.DependsOn = []string{lambbaCustomAuthorizer}

	if nil != api {
		apiGatewayResource, _ := api.NewResource("/hello", lambdaFn)

		// We only return http.StatusOK
		apiMethod, apiMethodErr := apiGatewayResource.NewAuthorizedMethod("GET",
			gocf.Ref(lambbaCustomAuthorizer),
			http.StatusOK,
			http.StatusInternalServerError)
		if nil != apiMethodErr {
			panic("Failed to create /hello resource: " + apiMethodErr.Error())
		}
		// Whitelist the Authorization header so that we can check it
		apiMethod.Parameters["method.request.header.Authorization"] = true
		// The lambda resource only supports application/json Unmarshallable
		// requests.
		apiMethod.SupportedRequestContentTypes = []string{"application/json"}
	}
	// Create the custom authorizer
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

		////////////////////////////////////////////////////////////////////////////
		// API Gateway custom authorizer
		authResource := template.AddResource(lambbaCustomAuthorizer,
			&gocf.APIGatewayAuthorizer{
				Name:                         gocf.String("TokenBasedAuthorizer"),
				Type:                         gocf.String("TOKEN"),
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
		authResource.DependsOn = []string{lambdaAuthFn.LogicalResourceName()}
		template.AddResource(lambdaAuthRole,
			authLambdaRole())

		////////////////////////////////////////////////////////////////////////////
		// API Gateway permission
		perm := &gocf.LambdaPermission{
			Action:       gocf.String("lambda:InvokeFunction"),
			FunctionName: gocf.GetAtt(lambdaAuthFn.LogicalResourceName(), "Arn"),
			Principal:    gocf.String(sparta.APIGatewayPrincipal),
		}
		template.AddResource("APIGatewayAuthPerm", perm)

		////////////////////////////////////////////////////////////////////////////
		// Finally, customize the Gateway response
		// Ref: https://docs.aws.amazon.com/apigateway/api-reference/resource/gateway-response/
		// * https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-gateway-response-using-the-console.html
		// * https://forums.aws.amazon.com/thread.jspa?messageID=710770&#710770
		gatewayResponseResourceName := "Gateway403Response"
		gatewayResponseResource := &gocf.APIGatewayGatewayResponse{
			StatusCode:   gocf.String("403"),
			RestAPIID:    gocf.Ref(api.LogicalResourceName()).String(),
			ResponseType: gocf.String("ACCESS_DENIED"),
			ResponseParameters: map[string]interface{}{
				"gatewayresponse.header.Access-Control-Allow-Origin":  "'*'",
				"gatewayresponse.header.Access-Control-Allow-Headers": "'*'",
			},
		}
		template.AddResource(gatewayResponseResourceName,
			gatewayResponseResource)
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
