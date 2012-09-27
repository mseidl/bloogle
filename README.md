bloogle
=======

Open source blog using Google App Engine(GAE)!

Overview:

This blog is very simple, and not *quite* ready to be used... but close.  You could actually start blogging now, but there are some security issues that need to be resolved.

Before running, there is a variable 'ecv' that gets added to hmac when hashing cookie values.  This is commented out, you need to pick out a value to use.  

Dependencies:

1. This blog uses passlib 1.6.1 from http://passlib.googlecode.com/files/passlib-1.6.1.tar.gz
To use this with GAE simply extract the tar and copy the passlib folder from the passlib-1.6.1 folder into the folder, and that is it.  No need to edit anything else.

2. Write an app.yaml so it uploads to your own Google account.  We will add one as a demo shortly.

TODO:
Rate limit login attempts by account.

Breakup single py file... 

Add configuration file

Add comments



