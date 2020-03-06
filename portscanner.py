#coding:utf-8
#Author:ghtwf01
#time:2020/3/6 16:46
import optparse
import dns.resolver
import console
import urllib3
from socket import *
from multiprocessing import Pool
import re
import time
def portsscan(host,port):
    #多端口扫描
    try:
        connect = socket(AF_INET,SOCK_STREAM)
        connect.settimeout(0.3)
        connect.connect((host,port))
        banner = getbanner(host,port)
        print("[+]"+str(port)+" /tcp open "+banner)
    except:
        pass
def portscan(host,port):
    #单端口扫描
    port = int(port)
    try:
        connect = socket(AF_INET, SOCK_STREAM)
        connect.settimeout(0.2)
        connect.connect((host, port))
        banner = getbanner(host,port)
        print("[+]" + str(port) + " /tcp open "+banner)
    except:
        print("[-]%s /tcp close" % port)
def getbanner(host,port):
    #获取网站容器
    connect = socket(AF_INET, SOCK_STREAM)
    connect.settimeout(0.1)
    connect.connect((host, port))
    try:
        banner = str(connect.recv(100))[2:-5]
    except:
        if port == 80:
            banner = "http"
        elif port == 135:
            banner = "Microsoft Windows RPC"
        elif port == 443:
            banner = "https"
        elif port == 445:
            banner = "microsoft-ds"
        else:
            banner = "unknown"
    return banner
def domaintoip(domain):
    #域名转ip
    try:
        ip = getaddrinfo(domain,None)[0][4][0]
    except:
        return domain
    return ip
def getServer(url):
    urllib3.disable_warnings()
    http = urllib3.PoolManager()
    try:
        web = http.request("GET",url)
        if web.status == 200:
            Server = web.headers["Server"]
            return Server
    except:
        return "known server"
def ipordomain(host):
    #判断是域名还是ip
    if re.match(r"[a-z]+.\w+.[a-z]+", host):
        return "domain"
    elif re.match(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",host):
        return "ip"
    else:
        print("Please enter the correct address")
        exit(4)
def check_argv(host,port):
    #检查接收的参数
    if host == None or port == None:
        print(parser.usage)
        exit(0)
    if re.match('^http',host):
        print("example:www.ghtwf01.cn")
        exit(1)
    if ipordomain(host) == "domain":
        cdn_result = query_cname(host)
        if (cdn_result==False):
            pass
        else:
            if(check_cdn(cdn_result)):
                pass
        host = domaintoip(host)
    if ipordomain(host) == "ip":
        host = host
    server = getServer(host)
    print("[+]scanning for " + host + "......")
    print("[+]Server: " + str(server))
def check_port_or_ports(port,thread,start_time):
    #判断是单个还是多个端口
    if thread == None:
        thread = 20
    if re.findall('-',port):
        pool = Pool(thread)
        port1 = port.split('-')
        for port in range(int(port1[0]), int(port1[1])+1):
            pool.apply_async(portsscan,(host,port))
        pool.close()
        pool.join()
        end_time = float(time.time())
        print("This scan took "+str(round((end_time-start_time),3))+" s")
    else:
        portscan(host,port)
        end_time = float(time.time())
        print("This scan took " +str(round((end_time-start_time),3))+ "s")

def query_cname(domain):
    #查询域名cname解析记录
    try:
        cname_query = dns.resolver.query(domain, 'CNAME')
    except:
        return False
    for i in cname_query.response.answer:
        for j in i.items:
            cname = str(j)[:-1]
            return cname

def check_cdn(cname):
    #检查是否存在cdn
    cdn_cname = {
        "yunjiasu-cdn":"百度云加速",
        "kunlunar.com":"阿里云",
        "kunlunca.com":"阿里云",
        "kxcdn.com":"KeyCDN",
        "lswcdn.net":"Leaseweb",
        "lxcdn.com":"网宿科技",
        "lxdns.com":"网宿科技",
        "myqcloud.com":"腾讯云",
        "cdn.dnsv1.com":"未知",
        "jcloud-cdn.com":"京东云",
        "cdn":"未知"
    }
    for key,value in cdn_cname.items():
        if re.findall(key,cname):
            print("\033[1;31;40m 警告:检测到存在"+value+"cdn，如果要继续扫描请输入y，要退出请输入n: \033[0m")
            judge = input()
            if judge == "y":
                return True
            else:
                print("祝您生活愉快^_^ ，开心快乐每一天！")
                exit(2)
if __name__ == '__main__':
    print('''                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             
  ...................................................................................................................
  ...................................................................................................................
  ...................................................................................................................
  ...................................................................................................................
  ..@@@@@@@@\........................,]..............................................................................
  ..@@@...\@@@......................@@@..............................................................................
  ..@@@...*@@@..,@@@@@@@`...@@@/@@=@@@@@@.......,@@@@@@.../@@@@@^..@@@@@@\...=@@\@@@@\...@@@/@@@@`.../@@@@@`...@@@/@@
  ..@@@]]/@@@^./@@/...\@@\..@@@/`,..@@@.........@@@`....,@@@`...*..`...,@@^..=@@@..@@@^..@@@^.=@@@.,@@@..,@@^..@@@/`,
  ..@@@@@@[`...@@@.....@@@..@@@.....@@@.........,@@@@@\.=@@^......,@@@@@@@^..=@@^..=@@^..@@@...@@@.=@@@@@@@@^..@@@...
  ..@@@........\@@\.../@@/..@@@.....@@@`........`...\@@^,@@@`...*.@@^..=@@^..=@@^..=@@^..@@@...@@@.=@@@*...`...@@@...
  ..@@@.........,@@@@@@@`...@@@.....=@@@@.......@@@@@@/..*\@@@@@^.=@@@@/@@^..=@@^..=@@^..@@@...@@@..,@@@@@@^...@@@...
  ...................................................................................................................
  ...................................................................................................................
  ...................................................................................................................
  ..................................................................................................................
                                                                                                                                                                                                                                                                       
                                                                                                Author:ghtwf01
                                                                                                name:port scanner
                                                                                                blog:https://ghtwf01.cn
                                                                                                欢迎使用本扫描器^_^
    ''')
    #接收参数
    parser = optparse.OptionParser("-H <target host> -p <target port>")
    parser.add_option('-H', dest='host', type='string', help='目标ip')
    parser.add_option('-p', dest='port', type='string', help='目标端口')
    parser.add_option('-t', dest='thread', type='int', help='线程')
    (options, args) = parser.parse_args()
    host = options.host
    port = options.port
    thread = options.thread
    start_time = float(time.time())
    check_argv(host,port)
    check_port_or_ports(port, thread, start_time)