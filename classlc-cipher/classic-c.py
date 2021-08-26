country = [50, 64, 643, 112, 756, 724, 380, 682, 792, 764, 320, 840]
num = 26
for i in range(0, 12):
    str = country[i]
    numb = str % num
    print(chr(ord("a") + numb), end="")
print("")
print("END")
