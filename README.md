# cb-response-smb1-utility
A simple utility to check the status of and/or disable SMBv1 on Windows system via Cb Response's Live Response functionality.

Assuming that you’re already set up with [cbapi-python](https://github.com/carbonblack/cbapi-python), it’s as simple as:

    ./smb1-util.py 

The above will only report the status of SMB1 on each available system. It will not make any changes. 

If you want to explicitly disable SMB1, run with:

    ./smb1-util.py —disable-smb1

You can use --help for additional information.
