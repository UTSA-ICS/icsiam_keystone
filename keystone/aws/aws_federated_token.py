import boto.sts
import boto.iam
#
regions = boto.iam.regions()
print(regions)
iamconn = boto.iam.connect_to_region('universal')
print(iamconn)

roles = iamconn.list_roles()
#
print("The available roles are:")
print(roles.list_roles_response.list_roles_result.roles[1].arn)
role1 = roles.list_roles_response.list_roles_result.roles[1].arn
#
#

stsconnection = boto.sts.connect_to_region('us-east-1')
#fd_token  = stsconnection.get_federation_token("khalid")
fd_token = stsconnection.assume_role(role1, 'session1')

print("\nThe Token user details are:")
print(fd_token.user)
print("User ARN: ", fd_token.user.arn)
print("Assume Role ID: ", fd_token.user.assume_role_id)

print("\nThe Token Credential details are:")
print(fd_token.credentials)
print("Access Key: ", fd_token.credentials.access_key)
print("Secret Key: ", fd_token.credentials.secret_key)
print("Session Token: ", fd_token.credentials.session_token)
print("Expiration: ", fd_token.credentials.expiration)

