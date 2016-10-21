# ChangeRootPassword_Sol
Works on Solaris only at present
Generates and returns a clear text password based on password length and dictionary specified - change these variables at the top of the script as necessary.
# output log file
LOG=/var/log/passwd.log
# length of password to generate
LENGTH=8
# number of times to attempt password generation before failing (to prevent runaway loop)
ITERATIONS=50
# alphabet for password generation (note - all the special characters have been tested and work with this script)
STRING='q w e r t y u i o p a s d f g h j k l z x c v b n m Q W E R T Y U I O P A S D F G H J K L Z X C V B N M 1 2 3 4 5 6 7 8 9 0 _ - ! = % & + . @ ~'
This clear text password is then used to replace the existing Solaris root password with a new one and will use the same encryption type and salt as the original when generating the encrypted hash.

The output is currently customised for BladeLogic automation but can be amended to suit any environment or automation technology
# The below line will echo out what we need for bladelogic 
# it requires "," to delimit chars to interpret translate to csv - if we use comma only, then bladelogic removes it
echo "password_change"'","'`hostname`'","'`hostid`'","'$CLEAR_PASSWD

How to run:
amend LENGTH, STRING variables as required (as shown above)
amend output requirements as required (as shown above)
run the script on the server(s) in question, either directly on the server or via whatever automation method is in use.
