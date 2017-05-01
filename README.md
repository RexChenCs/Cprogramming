# A chat service in C with the Linux Operating System to support a login queue with the specified number of users to consume the login requests in the same time.
# Allowed Wolfie Chat server and client thread safe throug hthe use of various locking mechanisms.
# The service was implemented to support Wolfie Protocol( custormized protocol under TCP).
# Multi Threads was used to build in the login and communicaiton process.
# The sql database was embed in the users password collection with basic security.
# Using Socketpair to customize the chat window along with xterm technique.
# Deep understanding and about I/O multiplexing and the control of kernel.
# Implement a producer/consumer login queue on the server which will be used to manage all of the login requests.
