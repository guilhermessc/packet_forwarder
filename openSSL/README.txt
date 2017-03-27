# README #


### to encrypt run: ###

openssl enc -aes-128-ecb -in test.txt -out test-enc.bin
#set the password to: "12345678"

###################################

### to decrypt run: ###

openssl enc -d -aes-128-ecb -in test-enc.bin -pass pass:12345678
