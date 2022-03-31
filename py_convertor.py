import subprocess

operand_list = [
    "sub rdx, rdx"
    ]


for item in operand_list:
    print (item)
    stdoutdata = subprocess.getoutput("rasm2 -a x86 -b 64 '{}'".format(item))
    print (stdoutdata)


