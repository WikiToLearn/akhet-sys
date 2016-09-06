import os

def akhet_logger(msg):
    d = os.path.dirname("/var/log/akhet/")
    if not os.path.exists(d):
        os.makedirs(d)
    with open("/var/log/akhet/akhet.log", "a") as myfile:
        myfile.write("{}\n".format(msg))
        myfile.close()
    print(str(msg))
