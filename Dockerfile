#
# Python Dockerfile
#
# https://github.com/dockerfile/python
#

# Pull base image.
FROM python

# Install Python.
RUN \
  pip install docker-py flask && \
  mkdir -p /code

# Define working directory.
WORKDIR /code

ADD dockerserver.py /code/dockerserver.py

# Define default command.
CMD ["bash"]