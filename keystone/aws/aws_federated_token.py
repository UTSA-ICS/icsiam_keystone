import boto.sts
import boto.iam
import exceptions
from boto.ec2.connection import EC2Connection

def generate_sts_token(role_name):
    regions = boto.iam.regions()
    iamconn = boto.iam.connect_to_region('universal')
    roles = iamconn.list_roles()

    rolefound = False
    for r in roles.list_roles_response.list_roles_result.roles:
	if role_name == r.role_name:
    		myrole = r.arn
		rolefound = True
		break
    if not rolefound:
	raise Exception("User Not authorized to access AWS")
	
    stsconnection = boto.sts.connect_to_region('us-east-1')
    fd_token = stsconnection.assume_role(myrole, 'mysession')
    
    #print("\nThe Token user details are:")
    #print(fd_token.user)
    #print("User ARN: ", fd_token.user.arn)
    #print("Assume Role ID: ", fd_token.user.assume_role_id)
    
    #print("\nThe Token Credential details are:")
    #print(fd_token.credentials)
    #print("Access Key: ", fd_token.credentials.access_key)
    #print("Secret Key: ", fd_token.credentials.secret_key)
    #print("Session Token: ", fd_token.credentials.session_token)
    #print("Expiration: ", fd_token.credentials.expiration)
    
    return fd_token.credentials

def use_sts_token():
    session_credential = generate_sts_token()
    conn = EC2Connection(aws_access_key_id=session_credential.access_key, aws_secret_access_key=session_credential.secret_key, security_token=session_credential.session_token)

def get_sns_url():
	session_credential = generate_sts_token()
	print "Done with getting session Token"

    # The issuer parameter specifies your internal sign-in
	# page, for example https://mysignin.internal.mycompany.com/.
	# The console parameter specifies the URL to the destination console of the
	# AWS Management Console. This example goes to Amazon SNS.
	# The signin parameter is the URL to send the request to.
	issuer_url = "http://10.245.123.39/icsiam"
	console_url = "https://console.aws.amazon.com/sns"
	signin_url = "https://signin.aws.amazon.com/federation"

	# Create the sign-in token using temporary credentials,
	# including the Access Key ID, Secret Access Key, and security token.
	session_json = json.dumps({
	  "sessionId":session_credential.access_key,
	  "sessionKey":session_credential.secret_key,
	  "sessionToken":session_credential.session_token
	})

	get_signin_token_url = signin_url + "?Action=getSigninToken" + \
		"&SessionType=json&Session=" + urllib.quote(session_json)
	returned_content = urllib2.urlopen(get_signin_token_url).read()

	#print "returned_content = ", returned_content

	signin_token = json.loads(returned_content)["SigninToken"]
	signin_token_param = "&SigninToken=" + urllib.quote(signin_token)
	#print signin_token_param

	# The issuer parameter is optional, but recommended. Use it to direct users
	# to your sign-in page when their session expires.
	issuer_param = "&Issuer=" + urllib.quote(issuer_url)
	destination_param = "&Destination=" + urllib.quote(console_url)

	login_url = signin_url + "?Action=login" + signin_token_param + \
	  issuer_param + destination_param

	print login_url

if __name__ == "__main__":
    use_sts_token()

