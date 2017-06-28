# cb-response-smb1-utility
A simple utility to check the status of and/or disable SMBv1 on Windows system via Cb Response's Live Response functionality.

Assuming that you’re already set up wih [cbapi-python](https://github.com/carbonblack/cbapi-python), a survey is as simple as:

    ./smb1-util.py 

The output status will be one of:
* smb1_enabled_default - The SMB1 subkey does not exist, meaning that SMBv1 is enabled by default. 
* smb1_enabled_explicit - The SMB1 subkey exists and is set to 1. This rarely occurs.
* cblr_timeout - The system is online but we couldn't get a Live Response session.
* error - An unhandled error during the Live Response routine.

The above will only report the status of SMB1 on each available system. It will not make any changes. 

If you want to explicitly disable SMB1, run with:

    ./smb1-util.py —disable-smb1

You can use --help for additional information.
