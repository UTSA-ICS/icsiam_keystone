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
print(roles.list_roles_response.list_roles_result.roles[0].arn)
role1 = roles.list_roles_response.list_roles_result.roles[0].arn
#
#

stsconnection = boto.sts.connect_to_region('us-east-1')
#fd_token  = stsconnection.get_federation_token("khalid")
fd_token = stsconnection.assume_role(role1, 'session1')

print(fd_token.federated_user_arn)
print(fd_token.packed_policy_size)

