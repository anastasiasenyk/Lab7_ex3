import hashlib

# If all goes well, we can add a user with a username and password; the User object is created and inserted into a
# dictionary.
# But in what ways can all not go well? Well, clearly we don't want to add a user with a username that
# already exists in the dictionary. If we did so, we'd overwrite an existing user's data and the new user might have
# access to that user's privileges. So, we'll need a UsernameAlreadyExists exception. Also, for security's sake,
# we should probably raise an exception if the password is too short. Both of these exceptions will extend
# AuthException, which we mentioned earlier.


class AuthException(Exception):
    def __init__(self, username, user=None):
        super().__init__(username, user)
        self.username = username
        self.user = user


class UsernameAlreadyExists(AuthException):
    pass


class PasswordWithoutNumbers(AuthException):
    pass


class PasswordWithoutBigSmallLetters(AuthException):
    pass


class PasswordTooShort(AuthException):
    pass


class InvalidUsername(AuthException):
    pass


class InvalidPassword(AuthException):
    pass


class UserHasPermission(AuthException):
    pass


class PermissionError(Exception):
    pass


class NotLoggedInError(AuthException):
    pass


class NotPermittedError(AuthException):
    pass


class User:
    def __init__(self, username, password):
        """Create a new user object. The password
        will be encrypted before storing."""
        self.username = username
        self.password = self._encrypt_pw(password)
        self.is_logged_in = False

    def _encrypt_pw(self, password):
        """Encrypt the password with the username and return
        the sha digest."""
        hash_string = self.username + password
        hash_string = hash_string.encode("utf8")
        return hashlib.sha256(hash_string).hexdigest()

    def check_password(self, password):
        """Return True if the password is valid for this
        user, false otherwise."""
        encrypted = self._encrypt_pw(password)
        return encrypted == self.password


class Authenticator:
    users = {}

    def __init__(self):
        """Construct an authenticator to manage
        users logging in and out."""

    def add_user(self, username, password):
        if username in Authenticator.users:
            raise UsernameAlreadyExists(username)
        if len(password) < 6:
            raise PasswordTooShort(username)
        if not any(char.isdigit() for char in password):
            raise PasswordWithoutNumbers(username)
        if password.lower() == password or password.upper() == password:
            raise PasswordWithoutBigSmallLetters(username)
        Authenticator.users[username] = User(username, password)

    def login(self, username, password):
        try:
            user = Authenticator.users[username]
        except KeyError:
            raise InvalidUsername(username)

        if not user.check_password(password):
            raise InvalidPassword(username, user)

        user.is_logged_in = True
        return True

    def is_logged_in(self, username):
        if username in Authenticator.users:
            return Authenticator.users[username].is_logged_in
        return False


class Authorizor:
    def __init__(self, authenticator):
        self.authenticator = authenticator
        self.permissions = {}

    def add_permission(self, perm_name):
        """Create a new permission that users
        can be added to"""
        try:
            perm_set = self.permissions[perm_name]
        except KeyError:
            self.permissions[perm_name] = set()
        else:
            raise PermissionError("Permission Exists")

    def permit_user(self, perm_name, username):
        """Grant the given permission to the user"""
        try:
            perm_set = self.permissions[perm_name]
        except KeyError:
            raise PermissionError("Permission does not exist")
        else:
            if username not in authenticator.users:
                raise InvalidUsername(username)
            if username in perm_set:
                raise UserHasPermission(username)
            else:
                perm_set.add(username)

    def check_permission(self, perm_name, username):
        if not self.authenticator.is_logged_in(username):
            raise NotLoggedInError(username)
        try:
            perm_set = self.permissions[perm_name]
        except KeyError:
            raise PermissionError("Permission does not exist")
        else:
            if username not in perm_set:
                raise NotPermittedError(username)
            else:
                return True


authenticator = Authenticator()

authorizor = Authorizor(authenticator)
