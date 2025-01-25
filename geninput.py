import random
import string

# Define the length of the string in terms of number of characters (3000 characters)
length = 200

# Define a pool of characters to pick from (including letters, digits, punctuation, etc.)
characters_pool = string.ascii_letters + string.digits  + ""  # Add more characters if you need

# Generate the random string
random_string = ''.join(random.choice(characters_pool) for _ in range(length))

# Print the random string or save it to a file
print(random_string)

