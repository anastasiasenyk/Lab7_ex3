import auth


class Editor:
    def __init__(self):
        self.username = None
        self.menu_map = {
            "login": self.login,
            "create": self.add_profile,
            "test": self.test,
            "change": self.change,
            "set": self.set,
            "quit": self.quit,
        }

    def add_profile(self):
        created = False
        while not created:
            username = input("username: ")
            password = input("your password: ")
            try:
                auth.Authenticator().add_user(username, password)
            except auth.UsernameAlreadyExists:
                print('Sorry, username already exists')
            except auth.PasswordTooShort:
                print('Sorry, password must be longer than 6 characters')
            except auth.PasswordWithoutNumbers:
                print('Sorry, password must contain numbers')
            except auth.PasswordWithoutBigSmallLetters:
                print('Sorry, password must contain both big and small letters')
            else:
                print('Great!')
                if len(auth.Authenticator.users.keys()) == 1:
                    print('You are first user! Lucky one! You have all permissions!')
                    auth.authorizor.add_permission("test program")
                    auth.authorizor.add_permission("change program")
                    auth.authorizor.add_permission("set permission")
                    auth.authorizor.permit_user("test program", username)
                    auth.authorizor.permit_user("change program", username)
                    auth.authorizor.permit_user("set permission", username)
                else:
                    print('You only have user permissions')
                created = True
                auth.authenticator.login(username, password)
                self.username = username

    def login(self):
        logged_in = False
        if auth.Authenticator().users == {}:
            print('No profile created yet')
            logged_in = True
        while not logged_in:
            username = input("username: ")
            password = input("password: ")
            try:
                logged_in = auth.authenticator.login(username, password)
            except auth.InvalidUsername:
                print("Sorry, that username does not exist")
            except auth.InvalidPassword:
                print("Sorry, incorrect password")
            else:
                self.username = username

    def is_permitted(self, permission):
        try:
            auth.authorizor.check_permission(permission, self.username)
        except auth.NotLoggedInError as e:
            print("{} is not logged in".format(e.username))
            return False
        except auth.NotPermittedError as e:
            print("{} cannot {}".format(e.username, permission))
            return False
        else:
            return True

    def test(self):
        if self.is_permitted("test program"):
            print("Testing program now...")

    def change(self):
        if self.is_permitted("change program"):
            print("You can add permission to other users.")

    def set(self):
        if self.is_permitted("set permission"):
            if len(auth.Authenticator.users.keys()) == 1:
                print('There are no other users but you')
            else:
                print("""
You can provide users with these permissions:
-> "test program"
-> "change program"
-> "set permission" """)
                while True:
                    username = input('Enter username: ')
                    permission = input('Enter name of permission: ')
                    try:
                        auth.authorizor.permit_user(permission, username)
                    except auth.PermissionError:
                        print('Permission does not exist')
                    except auth.InvalidUsername:
                        print('Username does not exist')
                    except auth.UserHasPermission:
                        print('The user already has this permission')
                    else:
                        print('Great!')
                        break

    def quit(self):
        raise SystemExit()

    def menu(self):
        try:
            answer = ""
            while True:
                print(Editor.menu_visual(self))
                answer = input("enter a command: ").lower()
                try:
                    func = self.menu_map[answer]
                except KeyError:
                    print("{} is not a valid option".format(answer))
                else:
                    func()
        finally:
            print("Thank you for testing the auth module")

    def menu_visual(self):
        if self.username is None:
            username = ''
        else:
            username = self.username
        menu_visual = f"""
Hello, {username} :)
Please enter a command:
\tlogin\t- login
\tcreate\t- create profile"""
        if self.username:
            perm_dict = auth.authorizor.permissions
            for permission in perm_dict.keys():
                if self.username in perm_dict[permission]:
                    menu_visual += f"""\n\t{permission.split(' ')[0]}\t- {permission}"""

        return menu_visual + "\n\tquit\t- quit"


Editor().menu()
