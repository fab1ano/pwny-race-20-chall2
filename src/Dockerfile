############################################################
# Dockerfile to host a binary challenge
############################################################

# Set the base image to ubuntu
FROM ubuntu:20.04

# File Author / Maintainer
MAINTAINER fabiano

# Add challenge files
ADD flag.txt /flag.txt
ADD chall /chall

# Expose ports
EXPOSE 4444:4444

# Set the default command
WORKDIR /
CMD /chall
