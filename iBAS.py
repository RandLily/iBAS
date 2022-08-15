import re, struct, argparse, array, idaapi

def get_differences(ptrs):
    differences = array.array("L")
    last = 0
    for ptr in ptrs:
        differences.append(ptr - last)
        last = ptr
    return differences

# strs and ptrs are ordered, so we can make ordered search
# only counts every samplerate elem, adjusts at return
def count_str(ptrs, strs, offset):
    c = 0
    lastptr = 0
    for si in range(0, len(strs)):
        ptr = ptrs.find(struct.pack("<L", strs[si] + offset), lastptr)
        if ptr == -1:
            continue
        lastptr = ptr
        c += 1
    return c

def findbase(str_len=5, diff_len=10,output=10):
    path = idc.get_input_file_path()
    with open(path, "rb") as f:
        file = f.read()
    
    ptrs = set()
    for offset in range(0, len(file) - 4, 4):
        ptr = struct.unpack("<L", file[offset : offset + 4])[0]
        ptrs.add(ptr)
    ptrs = list(ptrs)
    ptrs.sort()
    print(f"total pointers found: {len(ptrs)}")
    
    print(f"scanning binary for strings len>={str_len}...")
    regexp = b"[ -~\\t\\r\\n]{%d,}" % str_len 
    pattern = re.compile(regexp)
    strs = []
    for m in pattern.finditer(file):
        strs.append(m.start())
    print(f"total strings found: {len(strs)}")
    
    str_diffs = get_differences(strs)
    ptr_diffs = get_differences(ptrs)

    # convert to bytes to use the python stringlib's find (mix of boyer-moore and horspool)
    # https://github.com/python/cpython/blob/main/Objects/stringlib/fastsearch.h
    ptrs_b = array.array("L", ptrs).tobytes()
    ptr_diffs_b = ptr_diffs.tobytes()
    
    found = set()
    hits=[]
    print(f"find differences of length: {diff_len}")
    for si in range(0, len(str_diffs) - diff_len):  
        str_b = str_diffs[si: si + diff_len].tobytes()
        pi = ptr_diffs_b.find(str_b)
        if pi == -1:
            continue
        pi //= ptr_diffs.itemsize
        offset = ptrs[pi] - strs[si]
        if offset < 0 or offset in found:
            continue
        found.add(offset)
        flag = count_str(ptrs_b, strs, offset)
        hits.append((flag,offset))
    if len(hits)==0:
        print("nonthing found , you might change the input args")
    else:
        print("if many baseaddrs printed , maybe more than one firmware")
        hits.sort()
        hits.reverse()
        for num,b  in hits[:output]:
            print(f"possible baseaddr:0x{b:x} hits:{num:d}")         

def rebase(baseaddr):
    offset=baseaddr-idaapi.get_imagebase()
    idaapi.ida_segment.rebase_program(offset,MSF_FIXONCE)

#arch Thumb2:1，Other:TODO
#for speed and accuracy, seach step might be 0x2、0x4、0x10、0x100、0x1000...default=0x100
def guessbase(minaddr,maxaddr,step=0x100,output=10,arch=1):
    path = idc.get_input_file_path()
    with open(path, "rb") as f:
        file = f.read()
    
    p=[]
    for offset in range(0, len(file) - 4, 4):
        p.append(struct.unpack("<L", file[offset : offset + 4])[0])
    point_address_list=[]
    guess_file_end = maxaddr + idaapi.retrieve_input_file_size()
    for i in range(len(p)):
        if p[i]>=minaddr and p[i]<=guess_file_end:
            p[i]-=arch
            if p[i] not in point_address_list:
                point_address_list.append(p[i])
    print(f"total pointers found: {len(point_address_list)}")
    
    disass_address_list = []
    fuction_start = ["B","LDR","PUSH"]
    #B:0xE0,LDR=0x68,PUSH=0xB5
    b=idaapi.get_imagebase()
    for offset in range(b, b+len(file), 2):
        ins=idaapi.print_insn_mnem(offset)
        if ins in fuction_start:
            disass_address_list.append(offset)
    print(f"total functions found: {len(disass_address_list)}")
    
    print(f"scanning binary for step={step:x}...")
    hits=[]
    for guess_addr in range(minaddr,maxaddr,step):
        flag = 0
        for i in disass_address_list:
            if (i + guess_addr) in point_address_list:
                flag+=1
        hits.append((flag,guess_addr))
    hits.sort()
    hits.reverse()
    print("if many baseaddrs printed , maybe more than one firmware")
    for num,b  in hits[:output]:
        if num==0:
            break
        print(f"possible baseaddr:0x{b:x} hits:{num:d}")
