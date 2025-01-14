import hashlib

# Simulated function to get stored password hash
def get_stored_password_hash(username):
    """
    Simulate retrieving a stored password hash for a given username.
    Replace this with a secure database query in a real application.
    """
    if username == "user1":
        # Return the SHA-256 hash of "secure_password"
        return hashlib.sha256("secure_password".encode()).hexdigest()
    else:
        return None

# Function to get user input for username and password
def get_user_input():
    """
    Prompt the user for their username and password.
    """
    username = input("Enter your username: ")
    password = input("Enter your password: ")
    return username, password

# Check the credentials
def check_credentials(username, password):
    """
    Validate the entered username and password by comparing
    the password's hash with the stored hash.
    """
    stored_password_hash = get_stored_password_hash(username)
    
    if stored_password_hash is None:
        print("User not found!")
        return

    # Hash the entered password
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    # Compare the entered password hash with the stored hash
    if password_hash == stored_password_hash:
        print("Login successful!")
    else:
        print("Invalid credentials!")

# Main function to run the login check
def main():
    """
    Main function to handle the login process.
    """
    username, password = get_user_input()
    check_credentials(username, password)

# Corrected if statement for script execution
if __name__ == "__main__":
    main()
