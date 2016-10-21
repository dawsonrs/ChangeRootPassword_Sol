#!/bin/ksh

#
# Script to replace root password with a new one based on the clear text password generated
# Will use the existing encryption type and salt as the original
#
## Robert Dawson
## Fujitsu Services
## v0.3
## 19 May 2010
#
### EXIT CODES ###
#
# 1 Error backing up shadow file (backup_shadow)
# 2 Error setting old hash (backup_shadow)
# 3 Error copying shadow file (backup_shadow)
# 4 Error setting ENCR_DESC (get_enc)
# 5 Error setting ENCR_TYPE (get_enc)
# 6 Error setting ENCR_DESC for DES (get_enc)
# 7 Error setting SALT for DES (get_salt)
# 8 Error setting SALT (get_salt)
# 9 Invalid encryption type (get_salt)
# 10 Invalid encryption description (get_salt)
# 11 Max iterations exceeded generating password (generate_clear_password)
# 12 Error setting initial index (generate_clear_password)
# 13 Error setting index (generate_clear_password)
# 14 Error setting previous index (generate_clear_password)
# 15 Error incrementing index (generate_clear_password)
# 16 Error constructing clear password (generate_clear_password)
# 17 Error incrementing password length (generate_clear_password)
# 18 Error incrementing count (generate_clear_password)
# 19 /usr/sfw/bin/openssl does not exist (encrypt_new_password)
# 20 Error setting ENCR_PASSWD for DES (encrypt_new_password)
# 21 Error setting ENCR_PASSWD (encrypt_new_password)
# 22 Invalid encryption description (encrypt_new_password)
# 23 Error setting START for DES (swap_root_password)
# 24 Error setting END for DES (swap_root_password)
# 25 Error setting EPOCH_SECONDS (swap_root_password)
# 26 Error setting EPOCH_DAYS (swap_root_password)
# 27 Error setting NEWROOTLINE for DES (swap_root_password)
# 28 Error creating new shadow file in temporary location (swap_root_password)
# 29 Error copying new shadow file into place (replace_shadow)
# 30 Error removing temp shadow file 1 (replace_shadow)
# 31 Error removing temp shadow file 1 (replace_shadow)

VERBOSE=0
[ "$1" == "-v" ] && VERBOSE=1

init()
# initialise all variables
# either with values or as null
{
# output log file
LOG=/var/log/passwd.log
# length of password to generate
LENGTH=8
# number of times to attempt password generation before failing (to prevent runaway loop)
ITERATIONS=50
# alphabet for password generation (note - all the special characters have been tested and work with this script)
STRING='q w e r t y u i o p a s d f g h j k l z x c v b n m Q W E R T Y U I O P A S D F G H J K L Z X C V B N M 1 2 3 4 5 6 7 8 9 0 _ - ! = % & + . @ ~'
START=
NEWROOTLINE=
TMPSHADOW=/tmp/shadow1
TMPSHADOW2=/tmp/shadow2
ENCR_DESC=
ENCR_TYPE=
SALT=
ENCR_PASSWD=
CLEAR_PASSWD=
#RANDOM=$$
OLDHASH=
TESTSTRING=
START=
END=
NEWROOTLINE=

}

backup_shadow()
# backup the shadow file and strip out the original hash
{
# empty out the temporary files
[ -f $TMPSHADOW ] && > $TMPSHADOW
[ -f $TMPSHADOW2 ] && > $TMPSHADOW2
# now back up original shadow file
cp /etc/shadow /etc/shadow.bak
[ $? -eq 0 ] || { echo "`date`: Error 1: Error backing up shadow file" >> $LOG; exit 1; }
# now make a copy of original shadow for this script to work with
cp /etc/shadow $TMPSHADOW
if [ $? -eq 0 ]
then
	OLDHASH=`awk -F: '$1 == "root" {print $2}' $TMPSHADOW`
	[ $? -eq 0 ] || { echo "`date`: Error 2: Error setting old hash" >> $LOG; exit 2; }
else
	echo "`date`: Error 3: Error copying shadow file" >> $LOG
	exit 3	
fi
}

get_enc()
# determine the password encryption type
{
if [ `echo $OLDHASH | cut -c1` = $ ]
# is this using DES based encryption or MD5, SHA, blowfish, etc?
# DES based hash will not begin with $
# all the rest will
then
	ENCR_DESC="OTHER"
	[ $? -eq 0 ] || { echo "`date`: Error 4: Error setting ENCR_DESC" >> $LOG; exit 4; }
	ENCR_TYPE=`echo "$OLDHASH" | awk -F$ '{print $2}'`
	[ $? -eq 0 ] || { echo "`date`: Error 5: Error setting ENCR_TYPE" >> $LOG; exit 5; }
	# this corresponds to an entry in /etc/security/crypt.conf and is tested later in get_salt function
else
	ENCR_DESC="DES"
	[ $? -eq 0 ] || { echo "`date`: Error 6: Error setting ENCR_DESC for DES" >> $LOG; exit 6; }
fi
}

get_salt()
# based on the encryption type, get the current salt
{
case $ENCR_DESC in
DES)	
	## just get the first 2 chars from the string
	SALT=`echo $OLDHASH | cut -c1-2`
	[ $? -eq 0 ] || { echo "`date`: Error 7: Error setting SALT for DES" >> $LOG; exit 7; };;
OTHER)
	## make sure the encryption type gathered is supported by the system
	grep "^$ENCR_TYPE" /etc/security/crypt.conf >/dev/null
	if [ $? -eq 0 ]
	then
		## SALT=`echo $OLDHASH | cut -c4-11`
		SALT=`echo "$OLDHASH" | awk -F$ '{print $3}'`
		[ $? -eq 0 ] || { echo "`date`: Error 8: Error setting SALT" >> $LOG; exit 8; }
	else
		echo "`date`: Error 9: Invalid encryption type" >> $LOG
		exit 9
	fi;;
*)
	echo "`date`: Error 10: Invalid encryption description" >> $LOG
	exit 10;;
esac
}

generate_clear_password()
#
# need to add error checking statements here
# need to add complexity rules as well
# i.e.
# checks for inclusion of: 
# 	special chars; numbers; uppercase letters; lowercase letters
#		tests for inclusion of chars, numbers and specials now included
# satisfy the following conditions:
# 	not dictionary words		
# 		not feasible with a random generation algorithm like this
# 	not based on data which can easily be guessed or obtained		
# 		this is satisfied by default by virtue of a random number generator
# 	free of consecutive, identical, all numeric, all alphabetic chars
#		checks now included for passwords of this type - regeneration enforced if checks failed
# 	min 8 chars		
# 		This is satisfied by the LENGTH variable (currently 8)
# 	not the same as any of the previous 12 passwords
#		unable to do this with this solution model as we need a history to check against
#		better suited to a client server model with agents and a central database
#
{
typeset -i INDEX
INDEX=1
typeset -i INDEX_PREV
INDEX_PREV=1

IFS_SAV="$IFS"
IFS=" "

# Put $STRING in an array for easier manipulation
for i in `echo $STRING`
do
	array[$INDEX]=$i
	((INDEX=INDEX+1))
done

STRING_LEN=${#array[*]}

IFS="$IFS_SAV"

typeset -i PWLEN
PWLEN=0

COUNT=0
COMPLIANT=NO
until [ $COMPLIANT == YES ]
do
	[ $COUNT -eq $ITERATIONS ] && { echo "`date`: Error 11: Max iterations exceeded generating password" >> $LOG; exit 11; }
	# restricting this loop to $ITERATIONS attempts to generate a password. To prevent a runaway loop.
	# $ITERATIONS set at the top of the script
	while [ "$PWLEN" -lt "$LENGTH" ]
	do
		INDEX_PREV=$INDEX
			# to ensure that they are the same to begin with (and that we enter the loop below)
			# this loop will ensure that no 2 consecutive chars are the same
			# and by extension that the chars are not all identical
		[ $? -eq 0 ] || { echo "`date`: Error 12: Error setting initial index" >> $LOG; exit 12; }
		until [ $INDEX -ne $INDEX_PREV ]
		do
			INDEX=$(($RANDOM % $STRING_LEN))
			[ $? -eq 0 ] || { echo "`date`: Error 13: Error setting index" >> $LOG; exit 13; }
		done
		INDEX_PREV=$INDEX
		[ $? -eq 0 ] || { echo "`date`: Error 14: Error setting previous index" >> $LOG; exit 14; }
		# change the value of this parameter for checking in the next loop iteration
		# the above modulus calculation will return an int from 0 to (string_len)-1
		# I really want an int from 1 to string_len
		# so...
		((INDEX=INDEX+1))
		[ $? -eq 0 ] || { echo "`date`: Error 15: Error incrementing index" >> $LOG; exit 15; }
		CLEAR_PASSWD="$CLEAR_PASSWD${array[$INDEX]}"
		[ $? -eq 0 ] || { echo "`date`: Error 16: Error constructing user password" >> $LOG; exit 16; }
		((PWLEN=PWLEN+1))
		[ $? -eq 0 ] || { echo "`date`: Error 17: Error incrementing password length" >> $LOG; exit 17; }
	done
	((COUNT=COUNT+1))
	[ $? -eq 0 ] || { echo "`date`: Error 18: Error incrementing count" >> $LOG; exit 18; }
	#1# check that the password contains special chars
	# remove alphanumeric chars and test to see if remaining string is null or not
	[ -z `echo $CLEAR_PASSWD |tr -d "[:alnum:]"` ] && { PWLEN=0; CLEAR_PASSWD=""; continue; }
		# if there are no special chars, re-run the outer loop to generate a new password
	#2# check that the password contains at least 1 digit
	# remove digits from the password string and test to see if the length shrinks or not
	TESTSTRING=`echo $CLEAR_PASSWD | tr -d "[:digit:]"`
	[ `echo ${#TESTSTRING}` -lt $LENGTH ] || { PWLEN=0; CLEAR_PASSWD=""; continue; }
		# if there is not at least 1 digit, re-run the outer loop to generate a new password
	#3# check that the password contains at least 1 lowercase char
	# remove lowercase chars from the password string and test to see if the length shrinks or not
	TESTSTRING=`echo $CLEAR_PASSWD | tr -d "[:lower:]"`
	[ `echo ${#TESTSTRING}` -lt $LENGTH ] || { PWLEN=0; CLEAR_PASSWD=""; continue; }
		# if there is not at least 1 lowercase char, re-run the outer loop to generate a new password
	#4# check that the password contains at least 1 uppercase char
	# remove uppercase chars from the password string and test to see if the length shrinks or not
	TESTSTRING=`echo $CLEAR_PASSWD | tr -d "[:upper:]"`
	[ `echo ${#TESTSTRING}` -lt $LENGTH ] || { PWLEN=0; CLEAR_PASSWD=""; continue; }
		# if there is not at least 1 uppercase char, re-run the outer loop to generate a new password
	# when we get this far, the password has numbers, letters, special chars, non-consecutive and non-identical chars
	COMPLIANT=YES
done
}

encrypt_new_password()
# based on encryption type, generate new hash using original salt
#
# first we need to ensure that the command we need actually exists on this system
# exit if it does not exist
# it is part of the SUNWopenssl-commands package
# hashes consist of characters chosen from a 64-character alphabet (., /, 0-9, A-Z, a-z)
# see shadow(4) man page
{
[ -x /usr/sfw/bin/openssl ] || { echo "`date`: Error 19: /usr/sfw/bin/openssl does not exist" >> $LOG; exit 19; }
if [ $ENCR_DESC == DES ]
then
	ENCR_PASSWD=`/usr/sfw/bin/openssl passwd -salt $SALT $CLEAR_PASSWD`
	[ $? -eq 0 ] || { echo "`date`: Error 20: Error setting ENCR_PASSWD for DES" >> $LOG; exit 20; }
elif [ $ENCR_DESC == OTHER ]
then
	ENCR_PASSWD=`/usr/sfw/bin/openssl passwd -$ENCR_TYPE -salt $SALT $CLEAR_PASSWD`
	[ $? -eq 0 ] || { echo "`date`: Error 21: Error setting ENCR_PASSWD" >> $LOG; exit 21; }
else
	echo "`date`: Error 22: Invalid encryption description" >> $LOG
	exit 22
fi
}

swap_root_password()
# replace root password hash in temp copy of /etc/shadow
{
START=`grep root $TMPSHADOW | awk -F: '{print $1}'`:
        # get the start of the line up to the password field
[ $? -eq 0 ] || { echo "`date`: Error 23: Error setting START for DES" >> $LOG; exit 23; }
END=`grep root $TMPSHADOW | awk -F: '{OFS=":"}{print $4,$5,$6,$7,$8,$9}'`
        # get the end of the line from the hash to the end
[ $? -eq 0 ] || { echo "`date`: Error 24: Error setting END for DES" >> $LOG; exit 24; }
EPOCH_SECONDS=`/usr/bin/truss /usr/bin/date 2>&1 | /usr/bin/awk '/^time/ {print $NF}'`
	# number of seconds since the epoch
[ $? -eq 0 ] || { echo "`date`: Error 25: Error setting EPOCH_SECONDS" >> $LOG; exit 25; }
EPOCH_DAYS=`expr $EPOCH_SECONDS / 86400`
	# number of days since the epoch.  Convert seconds from above to days
[ $? -eq 0 ] || { echo "`date`: Error 26: Error setting EPOCH_DAYS" >> $LOG; exit 26; }
NEWROOTLINE="$START""$ENCR_PASSWD":"$EPOCH_DAYS":"$END"
        # insert new hash and datestamp to make new entry for file
[ $? -eq 0 ] || { echo "`date`: Error 27: Error setting NEWROOTLINE for DES" >> $LOG; exit 27; }
	# now to create the new shadow file in a parallel location
	# we will search for the current line beginning with "root" and replace the line with our new one
	# note I have used "|" as a delimiter here instead of "/"
	# as it may be part of the encrypted hash and cause the statement to be misinterpreted
	# it is not part of the 64 char alphabet used by crypt.
cat $TMPSHADOW | sed 's|^root.*$|'$NEWROOTLINE'|' > $TMPSHADOW2
[ $? -eq 0 ] || { echo "`date`: Error 28: Error creating new shadow file in temporary location" >> $LOG; exit 28; }
}

replace_shadow()
# copy the new shadow file from TMPSHADOW2 location to overwrite original
{
cp $TMPSHADOW2 /etc/shadow
[ $? -eq 0 ] || { echo "`date`: Error 29: Error copying new shadow file into place" >> $LOG; exit 29; }
#
# uncomment below to have the script remove the initial shadow backup
#rm $TMPSHADOW
#[ $? -eq 0 ] || { echo "`date`: Error 30: Error removing temp shadow file 1" >> $LOG; exit 30; }
#
rm $TMPSHADOW2	
[ $? -eq 0 ] || { echo "`date`: Error 31: Error removing temp shadow file 2" >> $LOG; exit 31; }
}

#
#
# echo statements below added for testing and should be commented out or removed from the production version
#

init
backup_shadow
[ $VERBOSE -eq 1 ] && echo "OLDHASH = $OLDHASH"
get_enc
[ $VERBOSE -eq 1 ] && echo "ENCR_DESC = $ENCR_DESC"
[ $VERBOSE -eq 1 ] && echo "ENCR_TYPE = $ENCR_TYPE"
get_salt
[ $VERBOSE -eq 1 ] && echo "SALT = $SALT"
generate_clear_password
[ $VERBOSE -eq 1 ] && echo "CLEAR_PASSWD = $CLEAR_PASSWD"
encrypt_new_password
[ $VERBOSE -eq 1 ] && echo "ENCR_PASSWD = $ENCR_PASSWD"
swap_root_password
[ $VERBOSE -eq 1 ] && echo "START = $START"
[ $VERBOSE -eq 1 ] && echo "END = $END"
[ $VERBOSE -eq 1 ] && echo "EPOCH_SECONDS = $EPOCH_SECONDS"
[ $VERBOSE -eq 1 ] && echo "EPOCH_DAYS = $EPOCH_DAYS"
[ $VERBOSE -eq 1 ] && echo "NEWROOTLINE = $NEWROOTLINE"
#replace_shadow
echo "`date`: root password successfully changed" >> $LOG
# The below line will echo out what we need for bladelogic 
# it requires "," to delimit chars to interpret translate to csv - if we use comma only, then bladelogic removes it
echo "password_change"'","'`hostname`'","'`hostid`'","'$CLEAR_PASSWD
exit 0
