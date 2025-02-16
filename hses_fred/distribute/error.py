class OverfullACLException(Exception):
    def __init__(self, acl_owner, acl_size, max_size):
        super().__init__(f'ACL of {acl_owner} violates maximal ACL rule count ({acl_size}/{max_size}) after distribution.')
        self.acl_owner = acl_owner
        self.acl_size = acl_size
        self.max_size = max_size

    def __str__(self):
        return super().__str__() + '\n'