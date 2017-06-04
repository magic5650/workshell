#!/bin/bash
#set -x
#set -e
# 执行服务器IP:  61.160.36.32
#检查结果
# type=0 是CDN,输出为:{"type":0,"ips":""}
# type=1 是VIP问题,输出为:{"type":1,"ips":""}
# type=2 是nginx,输出为:{"type":2,"ips":"183.136.136.121 183.61.6.74"}
# type=3 后端,输出为:{"type":2,"ips":"183.136.136.121:8089 183.61.6.74:8089"}
# type=4 是未知问题,输出为:{"type":4,"ips":""}
# type=5 是检查出错,输出为:{"type":5,"ips":""}
# type=6 站点不在WEB上下线,检查nginx,VIP正常,输出为:{"type":6,"ips":"...."}
 
# 1.没上CDN,上了WEB专区——检查后端——检查代理——检查VIP,返回1 or 2 or 3 or 4;
# 2.没上CDN,没上WEB专区——检查后端,返回3 or 4;
# 3.上了CDN,上了WEB专区——检查后端,检查代理——检查VIP,返回1 or 2 or 4 or 0;
# 4.上了CDN,没上WEB专区——检查后端,返回3 or 0;
# 5.检查出错,返回5;
# 6.上了WEB专区,但不在WEB上下线,检查代理——检查VIP,类型为6,返回6 or 1 or 2
 
# 时间差计算
function getTiming()
{
  local start=$1
  local end=$2

  local start_s=$(echo "$start" | cut -d '.' -f 1)
  local start_ns=$(echo "$start" | cut -d '.' -f 2)
  local end_s=$(echo "$end" | cut -d '.' -f 1)
  local end_ns=$(echo "$end" | cut -d '.' -f 2)
  local time_micro=$(( (10#$end_s-10#$start_s)*1000000 + (10#$end_ns/1000 - 10#$start_ns/1000) ))
  local time_ms=$(expr $time_micro/1000 | bc)
 
  echo "${time_ms}ms"
 
}
 
#设定host,检查url,返回200或其他;@params hostIP url queryData
function checkUrl()
{
 
  local IP=$1;
  local URL=$2;
  local HostUrl="";
  local Domain="";
  local code="";
  local temp_code="";
  local temp_time="";
 
  Domain=$(echo "${URL}"|sed "s!https://!!"|sed "s!http://!!"|awk -F "[/:]" '{print $1}');
 
  if [[ $(echo "${URL}"|grep -c "^https") -eq 1 ]]
    then
    #HostUrl=$(echo "${URL}"|sed "s/${Domain}/${IP}\:443/");
    HostUrl="${URL//${Domain}/${IP}:443}";
    temp_code=$(\
    sudo curl -k -s \
    -o /dev/null \
    -m 10 --retry 1 --retry-delay 1 \
    -A "Mozilla/5.0 (Windows NT 6.1; WOW64)" \
    -H "Cache-Control: no-cache" \
    -H "Host:${Domain}" \
    -w "%{response_code} %{time_total}" "${HostUrl}");
  else 
    #HostUrl=$(echo ${URL}|sed "s/${Domain}/${IP}/");
    HostUrl="${URL//${Domain}/${IP}}";
    temp_code=$(\
    sudo curl -s \
    -o /dev/null \
    -m 10 --retry 1 --retry-delay 1 \
    -A "Mozilla/5.0 (Windows NT 6.1; WOW64)" \
    -H "Cache-Control: no-cache" \
    -H "Host:${Domain}" \
    -w "%{response_code} %{time_total}" "${HostUrl}");
  fi
 
  code=$(echo "${temp_code}"|awk '{print $1}');
  temp_time=$(echo "${temp_code}"|awk '{print $2}');
  echo "${IP},${code},${temp_time}s" >> "$temp_file";
  echo "${code}";
 
}
 
#批量检查host,@params url hostArray() queryData
function checkHostArray()
{
 
  local url=$1;
  local hostArray=($2);
  for ip in ${hostArray[*]}
  do
  {
    echo "${ip},$(checkUrl "${ip}" "${url}")";
  }&
  done
  wait
 
}
 
#获取DNS记录 @params Domain
function getDNSIP()
{
 
  dnsType="A";
  local dnsArray=();
  local dnsRecord="";
  local dnsOwner="";
 
  local DNS="$1";
  local getDNSUrl="http://dns.sysop.duowan.com:63160/api/ex.html";
  local APPID="16";
  local APPKEY="e44b622c38d1a93ca28fb4a9e02cc07e";
  local MYRANDOM="abcdef";
  export local NOW;
  NOW=$(date +%Y%m%d%H%M);
  export local CYPHER;
  CYPHER=$(echo -n "${APPID}${APPKEY}${MYRANDOM}${NOW}" |sha1sum |awk '{print $1}');
        
  query="${getDNSUrl}?cypher=${CYPHER}&random=${MYRANDOM}&appid=${APPID}&class=OperatorController&method=searchAction&api_data=\{"%"22search_fuzzy_matching"%"22:"%"222"%"22,"%"22query"%"22:"%"22${DNS}"%"22,"%"22search_mode"%"22:"%"22dns"%"22,"%"22search_result_list"%"22:"%"221"%"22\}"
 
  dnsData=$(curl -s -m 10 \
  --retry 4 --retry-delay 3 \
  -H "Cache-Control: no-cache" \
  "${query}" 2>/dev/null);
 
  if [[ $? ]]
    then
    if [[ $(echo "$dnsData"|grep -c message) -eq 0 ]]
      then
      dnsType=$(echo "${dnsData}"|jq '.[].type' 2>/dev/null|head -1|sed 's/"//g');
      if [ "${dnsType}" = "CNAME" ]
        then
        dnsRecord=$(echo "${dnsData}"|jq '.[].record' 2>/dev/null|head -1|sed 's/"//g');
        dnsOwner=$(echo "${dnsData}"|jq '.[].owner' 2>/dev/null|head -1|sed 's/"//g');
        dnsArray=(${dnsType} ${dnsRecord});
      else
        dnsArray=($(echo "${dnsData}"|jq '.[]|select (.status == "1").record' 2>/dev/null|\
          sed 's/"//g'|tr " " "\n"|sort -nr|uniq));
        dnsOwner=$(echo "${dnsData}"|jq '.[]|select (.status == "1").owner'|head -1|sed 's/"//g')
      fi
      domainOwner="$dnsOwner"
    else
      dnsArray=("null");
    fi
  fi
 
  echo "${dnsArray[@]}";
 
}
 
#获取VIP列表
function getVIPList()
{
  local getProxyInfoUrl="http://bigdragon.yy.com/intf/getProxyInfo.jsp?username=dw_yaokangjun&pass=9be8d94672b1a2e0fa5240d550bd7af1";
  local VIPArray=();
  proxyData=$(curl -s -m 10 \
  --retry 4 --retry-delay 1 \
  -H "Cache-Control: no-cache" \
  ${getProxyInfoUrl} 2>/dev/null);
 
  #查找代理层nginxIP
  if [[ $? ]]
    then
    VIPArray=($(echo "${proxyData}" |jq '.data[]|select (.type <= 2)' 2>/dev/null|sed -n '/vip/p'|\
      sed -n '/[0-9]/p'|awk -F "\"" '{print $4}'|sort|uniq|xargs));
    echo "$proxyData" > "$vipInfoFile";
  else
    proxyData=$(sudo cat /home/fanweirui/lvsnginx.json)
    VIPArray=($(echo "${proxyData}" |jq '.data[]|select (.type <= 2)' 2>/dev/null|sed -n '/vip/p'|\
      sed -n '/[0-9]/p'|awk -F "\"" '{print $4}'|sort|uniq|xargs));
    echo "$proxyData" > "$vipInfoFile";
  fi
  echo "${VIPArray[@]}";
  
}
 
#获取WEB专区代理层的NginxIP @params dnsArray()
function getNginxServerIP()
{
 
  local getProxyInfoUrl="http://bigdragon.yy.com/intf/getProxyInfo.jsp?username=dw_yaokangjun&pass=9be8d94672b1a2e0fa5240d550bd7af1";
  local proxyData="";
  local dnsArray=($1);
  local nginxArray=();
 
  if [[ -f "$vipInfoFile" ]]
    then
    proxyData=$(cat "$vipInfoFile");
  else
    proxyData=$(curl -s -m 10 \
    --retry 4 --retry-delay 1 \
    -H "Cache-Control: no-cache" \
    ${getProxyInfoUrl} 2>/dev/null);
  fi
 
  #查找代理层nginxIP
  if [[ $? ]]
    then
    for dnsip in ${dnsArray[*]}
    do
      jsonData=$(echo "${proxyData}"|jq '.data[]|select (.type <= 2)' 2>/dev/null);
      line=$(echo "${jsonData}"|jq '.'|grep -m 1 "${dnsip}"|awk -F "\"" '{print $2}');
      nginxips=$(echo "${jsonData}"|jq --arg line "${line}" --arg ip "${dnsip}" '.|select (.[$line] == $ip).pIps' 2>/dev/null);
      OLD_IFS="$IFS";
      IFS="," ;
      tempArray=(${nginxips//\"/});
      IFS="$OLD_IFS";
      nginxArray=(${nginxArray[@]} ${tempArray[@]});
    done
  fi
 
  nginxArray=($(echo "${nginxArray[@]}"|tr " " "\n"|sort -nr|uniq));
  echo "${nginxArray[@]}";
  
}
 
#获取后端服务器IP @params Domain locaitonExp
function getRealServerIP()
{
  
  local Domain=$1;
  local locaitonExp=$2;
  local getRServerUrl="http://bigdragon.yy.com/intf/out/listLocationServers.jsp?username=dw_yaokangjun&pass=9be8d94672b1a2e0fa5240d550bd7af1&domain=${Domain}";
  local jsonData="";
  local regexArray=();
  local pathdepth=1;
  local matchlocation="/";
  local msg="";
  local rServerArray=();
 
  jsonData=$(curl -s -m 10 \
  --retry 4 --retry-delay 1 \
  -H "Cache-Control: no-cache" \
  "${getRServerUrl}" 2>/dev/null);
 
  msg=$(echo "${jsonData}"|jq '.msg' 2>/dev/null);
 
  if [[ $? ]] && [[ $msg = "\"success\"" ]]
    then
 
    locationArray=($(echo "${jsonData}"|jq '.data[].location' 2>/dev/null|sed 's/\"//g'));
 
    for location in ${locationArray[*]}
    do
      regex="^${location}";
      if [[ $locaitonExp =~ $regex ]];
        then
        regexArray=(${regexArray[@]} ${location});
      fi
    done
 
    length=${#regexArray[@]};
 
    for((i=0;i<"${length}";i++))
    do
      a=$(echo "${regexArray[$i]}"|grep -o '/'|wc -l);
      if [[ $a -gt $pathdepth ]]
        then
        matchlocation=${regexArray[$i]};
        pathdepth=$a;
      fi
    done
 
    rServerips=$(echo "${jsonData}"|\
    jq --arg arg "${matchlocation}" '.data[]|select(.location == $arg).nodes[]' 2>/dev/null);
    port=$(echo "${jsonData}"|\
    jq --arg arg "${matchlocation}" '.data[]|select(.location == $arg).port' 2>/dev/null|sed 's/"//g');
    rServerArray=($(echo "${rServerips}"|sed 's/"//g'|sed "s/$/:${port}/g"));
  fi
 
  if [[ $? ]] && [[ ! $msg = "\"success\"" ]]
    then
    rServerArray=("null");
  fi
 
  echo "${rServerArray[@]}";
 
}
 
#获取CDN源站IP @params Domain 
function getSourceServerIP()
{
 
  local Domain=$1;
  local getSourceServerUrl="http://cdn.sysop.duowan.com/intf/out/getSourceIps.jsp?domain=${Domain}";
  local sourceArray=();
  local jsonData="";
 
  jsonData=$(curl -s -m 10 \
  --retry 4 --retry-delay 1 \
  -H "Cache-Control: no-cache" \
  ${getSourceServerUrl} 2>/dev/null);
 
  if [[ $? ]]
    then
    sourceArray=($(echo "${jsonData}" |jq '.[]'|sed 's/"//g'));
    echo "${sourceArray[@]}";
  else
    echo "${sourceArray[@]}";
  fi
 
}
 
#根据CNAME，判断CDN厂商 @params CNAME
function getCDNCooperater()
{
  local CNAME=$1;
  local Cooper="";Cooper=$(echo "${CNAME}"|awk -F "." '{print $(NF-1)"."$NF}');
  case "${Cooper}" in
      cdn20.com|wscdns.com|wsdvs.com|wsglb0.com)  echo "网宿"
      ;;
      cloudglb.com|cloudcdn.net|cachecn.com|fwcdn.com)  echo "快网"
      ;;
      kunlungr.com|kunlunpi.com|kunlunle.com|kunlunhuf.com|kunlunea.com|alikunlun.net|kunlunno.com|kunlunca.com) echo "阿里"
      ;;
      xgslb.net)  echo "蓝汛"
      ;;
      fastcdn.com)  echo "帝联"
      ;;
      vdncloud.com)  echo "视界云"
      ;;
      dnsv1.com)  echo "腾讯云"
      ;;
      cdndo.com)  echo "UCloud"
      ;;
      bdydns.com)  echo "百度云"
      ;;
      "")  echo "未知"
      ;;
      *)  echo "其他"
      ;;
  esac
 
}

#根据IP，获取机器负责人信息
function get_tech_admin()
{
  #注意url参数中是否有+、空格、=、%、&、#等特殊符号
  local IP="$1"
  #要执行的脚本ID
  local shellId="106001"
  local URL="http://ido.sysop.duowan.com/intf/exeShellIntf.jsp"
  local queryData="pass=c5d2fe07e5460ed18d96379d420b8c38&dwName=dw_fanweirui&shellId=${shellId}&ips=${IP}&taskName=${IP}"
  local curldata=$(curl -s -m 3 --retry 1 "${URL}?${queryData}" 2>/dev/null);
  local queue="server_info"
  for (( i=0;i<5;i++ ))
  do
    sleep 1
    local server_json=$(curl -m 3 "http://183.136.136.18:1218/?charset=utf-8&name=${queue}&opt=get&auth=yysec123456")
    if [ ! "$server_json" = "HTTPMQ_GET_END" ];then
      echo $(echo "$server_json"|jq .responsibleAdmin_dw|sed 's!"!!g')
      return
    fi
  done
  echo "接口获取信息失败"
  # [ -n "$server_json" ] && echo $(echo "$getjson"|jq .responsibleAdmin_dw|sed 's!"!!g')
}

#CDN后缀名
#CDNsuffix="cdn20.com wscdns.com wsdvs.com wsglb0.com kunlungr.com kunlunpi.com kunlunle.com kunlunhuf.com kunlunea.com alikunlun.net kunlunno.com kunlunca.com cloudglb.com cloudcdn.net cachecn.com fwcdn.com vdncloud.com fastcdn.com xgslb.net bdydns.com dnsv1.com cdndo.com"
#临时文件记录返回码、服务器检测、服务器状态
temp_file=$(mktemp)
mail_file=$(mktemp)
trap 'rm -f ${temp_file} ${mail_file};exit' 1 2 3 15
check_start_time=$(date +%s.%N);
 
#查询的URL
[ -z "${web_url}" ] && inputUrl=$1 || inputUrl=$web_url
 
#检查结果
checkmsg="";
#查询url
#QUERYURL=$(echo "$inputUrl"|awk -F "?" '{print $1}');
QUERYURL=$(echo "$inputUrl")
#url携带参数
#QUERYDATA=$(echo "$inputUrl"|awk -F "?" '{print $2}');
#域名
Domain=$(echo "${QUERYURL}"|sed "s/http:\/\///"|sed "s/https:\/\///"|\
awk -F "[/:]" '{print $1}');
#站点路径
locaitonExp=$(echo "${QUERYURL}"|sed "s/http:\/\///"|sed "s/https:\/\///"|\
sed "s/${Domain}//"|sed "s/www.//"|sed "s/\:[0-9]*//");
#是否https链接
isHttps=0;
[[ "${QUERYURL}" =~ "https://" ]] && isHttps=1;
#http链接
HTTPURL="${QUERYURL//https/http}";
#VIP列表数据及nginx代理数据
#vipInfoFile="/home/fanweirui/lvsnginx.json";
vipInfoFile=$(mktemp lvsnginx.jsonXXX)
#nginx代理
nginxArray=();
#vip
vipList=();
vipList=($(getVIPList));
#dns记录
dnsArray=();
dnsArray=($(getDNSIP "${Domain}"));
#返回码列表
resCode=();
#CNAME记录
domainCname=$Domain;
comCount=1;
#源站记录
sourceArray=();
#域名负责人
domainOwner=""
 
if [ ${#dnsArray[@]} -eq 0 ]
  then
  checkmsg=$(echo -e "{\"type\":5,\"ips\":\"获取DNS信息失败，请重试\"}");
fi
 
if [ "${#dnsArray[@]}" -eq 1 ] && [ "${dnsArray[0]}" = "null" ]
  then
  checkmsg=$(echo -e "{\"type\":5,\"ips\":\"没有获取到域名的DNS记录，检查域名是否正确\"}");
fi
 
if [ ${#vipList[@]} -eq 0 ]
  then
  checkmsg=$(echo -e "{\"type\":5,\"ips\":\"获取VIP信息失败，请重试\"}");
fi

#判断是否CNAME到了别的域名，而不是CDN
if [ "${dnsArray[0]}" = "CNAME" ]
  then
  cnameDomain=$(echo "${dnsArray[1]}"|sed 's/\.$//');
  CDNCooper=$(getCDNCooperater "$cnameDomain")
  # 判断是否是上了CDN
  if [[ "$CDNCooper" == "其他" ]]
    then
    dnsArray=($(getDNSIP "${cnameDomain}"));
    domainCname=$cnameDomain;
 
    if [ ${#dnsArray[@]} -eq 0 ]
      then
      checkmsg=$(echo -e "{\"type\":5,\"ips\":\"获取DNS信息失败，请重试\"}");
    fi
    if [ ${#dnsArray[@]} -eq 1 ]
      then
      checkmsg=$(echo -e "{\"type\":5,\"ips\":\"没有获取到域名的DNS记录，检查域名是否正确\"}");
    fi
 
  fi
 
fi
 
if [ ${#dnsArray[@]} -gt 0 ] && [ ${#vipList[@]} -gt 0 ]
  then
 
  if [ "${dnsArray[0]}" = "CNAME" ]
    then
    #DNS类型为CDN,获取源站IP
    sourceArray=($(getSourceServerIP "${domainCname}"));
 
    #没有获取到源站信息，有可能是CNAME到其他域名，而没有上CDN
    if [ "${#sourceArray[@]}" -eq 0 ]
      then
      checkmsg=$(echo -e "{\"type\":5,\"ips\":\"没有获取到源站IP信息\"}");
    fi
 
    if [ ${#sourceArray[@]} -gt 0 ]
      then
      isVIP=0;
      for item in ${vipList[*]}; do [ "${sourceArray[0]}" = "$item" ] && isVIP=1 && break; done;
 
      #类型3,检查后端和代理和VIP,返回0 or 1 or 2 or 3;
      if [ $isVIP -eq 1 ]
        then
        realServerArray=($(getRealServerIP "${domainCname}" "${locaitonExp}"));
 
        if [ "${#realServerArray[@]}" -eq 1 ] && [ "${realServerArray[0]}" = "null" ]
          then
          checkmsg=$(echo -e "{\"type\":5,\"ips\":\"不在web上下线系统的业务！\"}");
          echo "realServer" >> "$temp_file";
          if [ -z "${RSErrorList}" ]
            then
            #检查proxy
            echo "Nginx" >> "$temp_file";
            proxyServer=($(getNginxServerIP "${dnsArray[*]}"));
            PSResult=$(checkHostArray "${QUERYURL}" "${proxyServer[*]}");
            PSErrorList=$(echo "${PSResult}"|awk -F "," '{if($2!~/^[2-4]0[0-4]$/)  {print $0}}');
 
            if [ -z "${PSErrorList}" ]
              then
              #检查VIP
              echo "LVS" >> "$temp_file";
              VIPResult=$(checkHostArray "${QUERYURL}" "${dnsArray[*]}");
              VIPErrorList=$(echo "${VIPResult}"|awk -F "," '{if($2!~/^[2-4]0[0-4]$/) {print $0}}');
 
              if [ -z "${VIPErrorList}" ]
                then
                checkmsg="{\"type\":6,\"ips\":\"后端服务器未探测\\nNginx代理节点正常\\nLVS节点均正常\"}";
              fi
 
              if [ -n "${VIPErrorList}" ]
                then
                msg=$(echo "${VIPErrorList}"|awk -F "," '{print $1}');
                checkmsg=$(echo -e "{\"type\":1,\"ips\":\"${msg}\"}");
              fi
 
            fi
 
            if [ -n "${PSErrorList}" ]
              then
              msg=$(echo "${PSErrorList}"|awk -F "," '{print $1}');
              checkmsg=$(echo -e "{\"type\":2,\"ips\":\"${msg}\"}");
            fi
          fi
        fi
 
        if [ "${#realServerArray[@]}" -eq 0 ]
          then
          checkmsg=$(echo -e "{\"type\":5,\"ips\":\"没有获取到后端服务器IP信息，请重试！\"}");
        fi
 
        if [ "${#realServerArray[@]}" -gt 0 ] && [ ! "${realServerArray[0]}" = "null" ]
          then
          #检查后端，使用HTTPURL
          echo "realServer" >> "$temp_file";
          RSResult=$(checkHostArray "${HTTPURL}" "${realServerArray[*]}");
          RSErrorList=$(echo "${RSResult}"|awk -F "," '{if($2!~/^[2-4]0[0-4]$/) {print $0}}');
 
          if [ -z "${RSErrorList}" ]
            then
            #检查proxy
            echo "Nginx" >> "$temp_file";
            proxyServer=($(getNginxServerIP "${sourceArray[*]}"));
            PSResult=$(checkHostArray "${QUERYURL}" "${proxyServer[*]}");
            PSErrorList=$(echo "${PSResult}"|awk -F "," '{if($2!~/^[2-4]0[0-4]$/) {print $0}}');
 
            if [ -z "${PSErrorList}" ]
              then
              #检查VIP
              echo "LVS" >> "$temp_file";
              VIPResult=$(checkHostArray "${QUERYURL}" "${sourceArray[*]}");
              VIPErrorList=$(echo "${VIPResult}"|awk -F "," '{if($2!~/^[2-4]0[0-4]$/) {print $0}}');
 
              if [ -z "${VIPErrorList}" ]
                then
                checkmsg="{\"type\":0,\"ips\":\"后端服务器正常\\nnginx代理节点正常\\nLVS节点均正常\\n站点上了CDN，请检查是否CDN问题!\"}";
              fi
 
              if [ -n "${VIPErrorList}" ]
                then
                msg=$(echo "${VIPErrorList}"|awk -F "," '{print $1}');
                checkmsg=$(echo -e "{\"type\":1,\"ips\":\"${msg}\"}");
              fi
 
            fi
 
            if [ -n "${PSErrorList}" ]
              then
              msg=$(echo "${PSErrorList}"|awk -F "," '{print $1}');
              checkmsg=$(echo -e "{\"type\":2,\"ips\":\"${msg}\"}");
            fi
 
          fi
 
          if [ -n "${RSErrorList}" ]
            then
            msg=$(echo "${RSErrorList}"|awk -F "," '{print $1}');
            checkmsg=$(echo -e "{\"type\":3,\"ips\":\"${msg}\"}");
 
          fi
 
        fi
 
      fi
 
      #直接检查后端,类型4,返回0 or 3;
      if [ $isVIP -eq 0 ]
        then
        #echo "类型4,返回0 or 3";
        #检查后端
        echo "realServer" >> "$temp_file";
        realServerArray=(${sourceArray[@]});
        RSResult=$(checkHostArray "${QUERYURL}" "${realServerArray[*]}");
        RSErrorList=$(echo "${RSResult}"|awk -F "," '{if($2!~/^[2-4]0[0-4]$/) {print $0}}');
 
        if [ -z "${RSErrorList}" ]
          then
          checkmsg="{\"type\":0,\"ips\":\"后端服务器正常\\n站点上了CDN，没接入web专区，请检查是否CDN问题！\"}";
        fi
 
        if [ -n "${RSErrorList}" ]
          then
          msg=$(echo "${RSErrorList}"|awk -F "," '{print $1}');
          [[ isHttps -eq 0 ]] && msg=$(echo "${msg}"|sed "s/ /\:80 /g"|sed 's/$/\:80/');
          [[ isHttps -eq 1 ]] && msg=$(echo "${msg}"|sed "s/ /\:443 /g"|sed 's/$/\:443/');
 
          checkmsg=$(echo -e "{\"type\":3,\"ips\":\"${msg}\"}");
        fi
      
      fi
    
    fi
  
  fi
 
  if [ "${dnsArray[0]}" != "CNAME" ]
    then
    isVIP=0;
    for item in ${vipList[*]}; do [ "${dnsArray[0]}" = "$item" ] && isVIP=1 && break; done;
 
    #类型2,直接检查后端,返回3 or 4；
    if [ $isVIP -eq 0 ]
      then
      #检查后端
      echo "realServer" >> "$temp_file";
      realServerArray=(${dnsArray[@]});
      RSResult=$(checkHostArray "${QUERYURL}" "${realServerArray[*]}");
      RSErrorList=$(echo "${RSResult}"|awk -F "," '{if($2!~/^[2-4]0[0-4]$/) {print $0}}');
 
      if [ -z "${RSErrorList}" ]
        then
        checkmsg=$(echo -e "{\"type\":4,\"ips\":\"后端服务器正常\"}");
      fi
 
      if [ -n "${RSErrorList}" ]
        then
        msg=$(echo "${RSErrorList}"|awk -F "," '{print $1}');
 
        if [[ $(echo "${QUERYURL}"|grep -c "${Domain}:[0-9]*") -eq 1 ]]
        then
          port=$(echo "${QUERYURL}"|grep -o "${Domain}:[0-9]*"|sed "s/${Domain}\://");
          msg=$(echo "${msg}"|sed "s/ /\:${port} /g"|sed "s/$/\:${port}/");
        else
          [[ isHttps -eq 0 ]] && msg=$(echo "${msg}"|sed "s/ /\:80 /g"|sed 's/$/\:80/');
          [[ isHttps -eq 1 ]] && msg=$(echo "${msg}"|sed "s/ /\:443 /g"|sed 's/$/\:443/');
        fi
 
        checkmsg=$(echo -e "{\"type\":3,\"ips\":\"${msg}\"}");
      fi
 
    fi
 
    #类型1,检查后端和代理和VIP,返回1 or 2 or 3 or 4;
    if [[ $isVIP -eq 1 ]]
      then
      realServerArray=($(getRealServerIP "${domainCname}" "${locaitonExp}"));
 
      if [ "${#realServerArray[@]}" -eq 1 ] && [ "${realServerArray[0]}" = "null" ]
        then
        checkmsg=$(echo -e "{\"type\":5,\"ips\":\"不在web上下线系统的业务！\"}");
        echo "realServer" >> "$temp_file";
        if [ -z "${RSErrorList}" ]
          then
          #检查proxy
          echo "Nginx" >> "$temp_file";
          proxyServer=($(getNginxServerIP "${dnsArray[*]}"));
          PSResult=$(checkHostArray "${QUERYURL}" "${proxyServer[*]}");
          PSErrorList=$(echo "${PSResult}"|awk -F "," '{if($2!~/^[2-4]0[0-4]$/)  {print $0}}');
 
          if [ -z "${PSErrorList}" ]
            then
            #检查VIP
            echo "LVS" >> "$temp_file";
            VIPResult=$(checkHostArray "${QUERYURL}" "${dnsArray[*]}");
            VIPErrorList=$(echo "${VIPResult}"|awk -F "," '{if($2!~/^[2-4]0[0-4]$/) {print $0}}');
 
            if [ -z "${VIPErrorList}" ]
              then
              checkmsg="{\"type\":6,\"ips\":\"后端服务器未探测\\nNginx代理节点正常\\nLVS节点均正常\"}";
            fi
 
            if [ -n "${VIPErrorList}" ]
              then
              msg=$(echo "${VIPErrorList}"|awk -F "," '{print $1}');
              checkmsg=$(echo -e "{\"type\":1,\"ips\":\"${msg}\"}");
            fi
 
          fi
 
          if [ -n "${PSErrorList}" ]
            then
            msg=$(echo "${PSErrorList}"|awk -F "," '{print $1}');
            checkmsg=$(echo -e "{\"type\":2,\"ips\":\"${msg}\"}");
          fi
        fi
      fi
 
      if [ "${#realServerArray[@]}" -eq 0 ]
        then
        checkmsg=$(echo -e "{\"type\":5,\"ips\":\"获取后端服务器IP失败，请重试！\"}");
      fi
 
      if [ "${#realServerArray[@]}" -gt 0 ] && [ ! "${realServerArray[0]}" = "null" ]
        then
        #检查后端
        echo "realServer" >> "$temp_file";
        [[ isHttps -eq 0 ]] && RSResult=$(checkHostArray "${QUERYURL}" "${realServerArray[*]}");
        [[ isHttps -eq 1 ]] && RSResult=$(checkHostArray "${HTTPURL}" "${realServerArray[*]}");
        RSErrorList=$(echo "${RSResult}"|awk -F "," '{if($2!~/^[2-4]0[0-4]$/) {print $0}}');
 
        if [ -z "${RSErrorList}" ]
          then
          #检查proxy
          echo "Nginx" >> "$temp_file";
          proxyServer=($(getNginxServerIP "${dnsArray[*]}"));
          PSResult=$(checkHostArray "${QUERYURL}" "${proxyServer[*]}");
          PSErrorList=$(echo "${PSResult}"|awk -F "," '{if($2!~/^[2-4]0[0-4]$/)  {print $0}}');
 
          if [ -z "${PSErrorList}" ]
            then
            #检查VIP
            echo "LVS" >> "$temp_file";
            VIPResult=$(checkHostArray "${QUERYURL}" "${dnsArray[*]}");
            VIPErrorList=$(echo "${VIPResult}"|awk -F "," '{if($2!~/^[2-4]0[0-4]$/) {print $0}}');
 
            if [ -z "${VIPErrorList}" ]
              then
              checkmsg="{\"type\":4,\"ips\":\"后端服务器正常\\nNginx代理节点正常\\nLVS节点均正常\"}";
            fi
 
            if [ -n "${VIPErrorList}" ]
              then
              msg=$(echo "${VIPErrorList}"|awk -F "," '{print $1}');
              checkmsg=$(echo -e "{\"type\":1,\"ips\":\"${msg}\"}");
            fi
 
          fi
 
          if [ -n "${PSErrorList}" ]
            then
            msg=$(echo "${PSErrorList}"|awk -F "," '{print $1}');
            checkmsg=$(echo -e "{\"type\":2,\"ips\":\"${msg}\"}");
          fi
        fi
 
        if [ -n "${RSErrorList}" ]
          then
          msg=$(echo "${RSErrorList}"|awk -F "," '{print $1}');
          checkmsg=$(echo -e "{\"type\":3,\"ips\":\"${msg}\"}");
        fi
 
      fi
 
    fi
 
  fi
 
fi
 
checkmsg="$checkmsg";
msgtype=$(echo $checkmsg|jq '.type');
message=$(echo $checkmsg|jq '.ips'|sed 's/\"//g');
 
###############edit by hujihai################
if [ "$msgtype" -eq 3 ] ;then
  error_ips=$(echo "$message"|awk -F : '{pring $1}')

  for ip in $error_ips
  do
    ping_ttl_count=$(/bin/ping $ip -c 5 -i 1|grep ttl |wc -l)
    if [ $ping_ttl_count -lt 4 ];then
      echo "后端 $ip 网络异常,丢包率超过20%"  >> $mail_file
    fi
  done

  for ip in $error_ips
  do
    web_port=$(echo "$message"|grep "${ip}:"|awk -F : '{pring $2}')
    port_status=$(echo -e "\n"|telnet $ip $web_port 2>/dev/null|grep "\^]"|wc -l)
    if [ $port_status -eq 0 ];then
      echo "后端 ${ip} 的WEB服务端口 ${web_port} 无法访问" >> $mail_file
    fi
  done
fi
###############edit by hujihai################
 
#######################################打印结果#######################################
Nginxnum=$(sed -n '/Nginx/p' "$temp_file"|wc -l)
if [[ "$Nginxnum" = "1" ]]
  then   
  rserverCodeList=$(sed -n '/realServer/,/Nginx/p' "$temp_file"|sed '1d'|sed '$d'|awk -F ',' '{print $1" "$2}');
  nginxCodeList=$(sed -n '/Nginx/,/LVS/p' "$temp_file"|sed '1d'|sed '$d'|awk -F ',' '{print $1" "$2}');
  lvsCodeList=$(sed -n '/LVS/,$p' "$temp_file"|sed '1d'|awk -F ',' '{print $1" "$2}');
else
  rserverCodeList=$(sed -n '2,$p' "$temp_file"|awk -F ',' '{print $1" "$2}');
  nginxCodeList="";
  lvsCodeList="";
fi
realServer40x=();rServerErrorIps=();nginx403=();lvsErrorIps=();nginx404=()
realServer40x=($(echo "$rserverCodeList"|awk '{if($2~/^40[3-4]/) {print $1}}'));
rServerErrorIps=($(echo "$rserverCodeList"|awk '{if($2!~/^[2-4]0[0-4]$/) print $1}'));
[[ "$Nginxnum" = "1" ]] && nginx403=($(echo "$nginxCodeList"|awk '{if($2~/^403/) print $1}'));
[[ "$Nginxnum" = "1" ]] && lvsErrorIps=($(echo "$lvsCodeList"|awk '{if($2!~/^[2-3]0[0-4]$/) print $1}'));
[[ "$Nginxnum" = "1" ]] && nginx404=($(echo "$nginxCodeList"|awk '{if($2~/^404/) print $1}'));
 
 
function urlInfoOutput(){
  echo -e "检测的URL为：${QUERYURL}";
  [[ $isHttps -eq 1 ]] && [[ $(echo "${resCode[@]}"|grep -c Nginx) -eq 1 ]] && echo "检测的后端的URL为：${HTTPURL}";
  echo -e "检测的域名为：${Domain}";
  echo -e "匹配的站点路径为：${locaitonExp}";
  echo -e "请求附加参数为：${QUERYDATA}";
 
}

function isIPVIP(){
  for item in ${vipList[*]}
  do
    ip=""
    if [[ "$1" = "$item" ]]    
      then
      ip="$1"
      break
    fi
  done
  [[ "$ip" = "$1" ]] && echo "0" || echo "1"
 
}
 
function DNSInfoOutput(){
 
  if [[ ! "$message" =~ "DNS" ]]
    then
    if [[ $comCount -eq 1 ]] && [[ "$domainCname" = "$cnameDomain" ]]
      then
      echo -e "域名${Domain}\nCNAME到了\n${cnameDomain}";
      echo -e "域名${cnameDomain}\nDNS解析记录为：";
    else
      echo -e "域名${Domain}\nDNS解析记录为：";
    fi
    for ip in ${dnsArray[*]}
    do
      echo $ip
    done
    if [[ ! "$CDNCooper" == "其他" ]]
      then
      echo "归属厂商：$CDNCooper";
      #echo "http://cdn.sysop.duowan.com/admin/cdn/domain_cname.jsp?domain=${domainCname}";
      echo "源站为："
      for ip in ${sourceArray[*]}
      do
        echo $ip
      done
    fi
  fi
 
}
 
function checkResultOutput() {
 
  if [[ $msgtype -eq 5 ]]
    then
    echo -e "$message";
  fi
 
  if [[ $msgtype -eq 0 ]] || [[ $msgtype -eq 4 ]]
    then
    if [[ ${#realServer40x[@]} -gt 0 ]]
      then
      echo -e "后端机器返回404or403";
    fi
 
    if [[ ${#realServer40x[@]} -eq 0 ]] && [[ ${#nginx403[@]} -gt 0 ]]
      then
      echo -e "后端服务器正常\n存在nginx代理异常返回403\n请检查server_name是否配置正确！";
    fi
 
    if [[ ${#realServer40x[@]} -eq 0 ]] && [[ ${#nginx404[@]} -gt 0 ]]
      then
      echo -e "后端服务器正常\n存在nginx代理异常返回404";
    fi
 
    if [[ ${#realServer40x[@]} -eq 0 ]] && [[ ${#nginx403[@]} -eq 0 ]] && [[ ${#lvsErrorIps[@]} -gt 0 ]] && [[ ${#nginx404[@]} -eq 0 ]]
      then
      notvipips=()
      for ip in ${lvsErrorIps[*]}
      do
        code=$(isIPVIP "$ip")
        [ "$code" -eq 1 ] && notvipips=("${notvipips[@]}" "$ip")
      done
      if [ ${#notvipips[@]} -eq 0 ];then
        echo -e "WEB专区LVS节点问题!";
      else
        for ip in ${notvipips[*]}
        do
          echo -e "访问非WEB专区VIP $ip 出错";
        done
      fi
    fi
 
    if [[ ${#realServer40x[@]} -eq 0 ]] && [[ ${#nginx403[@]} -eq 0 ]] && [[ ${#lvsErrorIps[@]} -eq 0 ]] && [[ ${#nginx404[@]} -eq 0 ]]
      then
      echo -e "未发现异常";
    fi
 
  fi
 
  if [[ $msgtype -eq 6 ]]
    then
    if [[ ${#nginx403[@]} -gt 0 ]]
      then
      echo -e "存在nginx代理异常返回403\n请检查server_name是否配置正确！";
    fi
 
    if [[ ${#nginx404[@]} -gt 0 ]]
      then
      echo -e "存在nginx代理异常返回404";
    fi
 
    if [[ ${#nginx403[@]} -eq 0 ]] && [[ ${#lvsErrorIps[@]} -gt 0 ]] && [[ ${#nginx404[@]} -eq 0 ]]
      then
      notvipips=()
      for ip in ${lvsErrorIps[*]}
      do
        code=$(isIPVIP "$ip")
        [ "$code" -eq 1 ] && notvipips=("${notvipips[@]}" "$ip")
      done
      if [ ${#notvipips[@]} -eq 0 ];then
        echo -e "WEB专区LVS节点问题!";
      else
        for ip in ${notvipips[*]}
        do
          echo -e "访问非WEB专区VIP $ip 出错";
        done
      fi
    fi
 
    if [[ ${#nginx403[@]} -eq 0 ]] && [[ ${#lvsErrorIps[@]} -eq 0 ]] && [[ ${#nginx404[@]} -eq 0 ]]
      then
      echo -e "未发现异常";
    fi
 
  fi
 
  if [[ $msgtype -eq 1 ]]
    then
    notvipips=()
    for ip in ${lvsErrorIps[*]}
    do
      code=$(isIPVIP "$ip")
      [ "$code" -eq 1 ] && notvipips=("${notvipips[@]}" "$ip")
    done
    if [ ${#notvipips[@]} -eq 0 ];then
      echo -e "WEB专区LVS节点问题!";
    else
      for ip in ${notvipips[*]}
      do
        echo -e "访问非WEB专区VIP $ip 出错";
      done
    fi
  fi
 
  if [[ $msgtype -eq 2 ]]
    then
    echo -e "WEB专区NGINX节点问题!";
  fi
 
  # if [[ $msgtype -eq 3 ]]
  #   then
  #   echo -e "访问后端节点异常!";
  # fi
 
}
 
function redCodeOutput(){
  if [[ $msgtype -ne 5 ]]
    then
    echo -e "\n检查的服务器返回码及时长为：";
    echo -e "IP             response_code    time";
    resCode=($(cat "$temp_file"));
    for code in ${resCode[*]}
    do
      if [[ ! "$code" =~ (Nginx|LVS|realServer) ]]
        then
        echo "${code}"|awk -F "," '{print $1"     "$2"      "$3}';
      else
        echo "${code}";
      fi
    done
 
    echo "有关http返回码的相关信息详见：";
    echo "http://ido.sysop.duowan.com/admin/faq/question/view.jsp?from=list&id=67001";
  fi
 
}
 
function getArchitecture(){
 
  if [[ $msgtype -ne 5 ]]
    then
    if [[ "${dnsArray[0]}" != "CNAME" ]] && [[ $isVIP -eq 0 ]]
      then
      echo "DNS—>后端机器";
    fi
    if [[ "${dnsArray[0]}" != "CNAME" ]] && [[ $isVIP -eq 1 ]]
      then
      echo "DNS—>WEB专区—>后端机器";
    fi
    if [[ "${dnsArray[0]}" = "CNAME" ]] && [[ $isVIP -eq 0 ]]
      then
      echo "DNS—>CDN—>后端机器";
    fi
    if [[ "${dnsArray[0]}" = "CNAME" ]] && [[ $isVIP -eq 1 ]]
      then
      echo "DNS—>CDN—>WEB专区—>后端机器";
    fi
  else
    echo "";
  fi
 
}
 
function getUserName(){
 
  [[ $msgtype -eq 5 ]] && echo "业务运维"
  [[ $msgtype -eq 1 ]] || [[ $msgtype -eq 2 ]] && echo "业务运维"
 
  if [[ $msgtype -eq 3 ]]
    then
    errorip=$(echo "${rServerErrorIps[0]}"|cut -d ":" -f1);
    tech_admin=$(get_tech_admin "$errorip");
    echo "rServerErrorIps ip is ${rServerErrorIps[0]}" 1>&2
    echo "$tech_admin";
  fi
 
  if [[ $msgtype -eq 0 ]] || [[ $msgtype -eq 4 ]] || [[ $msgtype -eq 6 ]]
    then
    if [[ ${#realServer40x[@]} -gt 0 ]]
      then
      realServer40xip=$(echo "${realServer40x[0]}"|cut -d ":" -f1)
      tech_admin=$(get_tech_admin "$realServer40xip");
      echo "realServer40x ip is ${realServer40xip}" 1>&2
      echo "$tech_admin";
    else
      echo "业务运维"
    fi
    # if [[ ${#realServer40x[@]} -eq 0 ]] && [[ ${#nginx403[@]} -gt 0 ]]
    #   then
    #   tech_admin=$(get_tech_admin "${nginx403[0]}");
    #   echo "nginx403 ip is {nginx403[0]}" 1>&2
    #   #echo "$tech_admin";
    #   echo "业务运维"
    # fi
 
    # if [[ ${#realServer40x[@]} -eq 0 ]] && [[ ${#nginx403[@]} -eq 0 ]]
    #   then
    #   #echo "dw_fanweirui"
    #   echo "业务运维"
    # fi
  fi
 
}
 
check_end_time=$(date +%s.%N);
echo "URL探测脚本执行时长为$(getTiming "$check_start_time" "$check_end_time")" 1>&2;
urlInfoOutput 1>&2
redCodeOutput 1>&2
 
rserverCodeList=$(echo "${rserverCodeList}"|sed 's!000!超时!g'|sed 's!$!</br>!g');
nginxCodeList=$(echo "${nginxCodeList}"|sed 's!000!超时!g'|sed 's!$!</br>!g');
lvsCodeList=$(echo "${lvsCodeList}"|sed 's!000!超时!g'|sed 's!$!</br>!g');
 
#checkUrlInfo=$(urlInfoOutput|sed 's!$!</br>!g');
domainDNSInfo=$(DNSInfoOutput|sed 's!$!</br>!g');
checkResultInfo=$(checkResultOutput|sed 's!^!<b><font color=\\"red\\">!g'|sed 's!$!</font></b></br>!g');
errorServerCheck=$(cat "$mail_file"|sed 's!^!<b><font color=\\"red\\">!g'|sed 's!$!</font></b></br>!g');
#checkResultInfo=$(checkResultOutput|sed 's!$!</br>!g');
#errorServerCheck=$(cat "$mail_file"|sed 's!$!</br>!g');
 
architecture=$(getArchitecture)
userName=$(getUserName)
if [[ ${#realServer40x[@]} -gt 0 ]];then
  nginxCodeList="后端问题无需探测";lvsCodeList="后端问题无需探测"
fi
if [[ $msgtype -eq 3 ]];then
  nginxCodeList="后端问题无需探测";lvsCodeList="后端问题无需探测"
fi
if [[ ${#realServer40x[@]} -eq 0 ]] && [[ ${#nginx403[@]} -gt 0 ]];then
  lvsCodeList="NGINX问题,无需探测LVS"
fi
if [[ ${#realServer40x[@]} -eq 0 ]] && [[ ${#nginx404[@]} -gt 0 ]];then
  lvsCodeList="NGINX问题,无需探测LVS"
fi
if [[ $msgtype -eq 2 ]] || [[ $msgtype -eq 1 ]] || [[ $msgtype -eq 6 ]];then
  if [ "${#realServerArray[@]}" -eq 1 ] && [ "${realServerArray[0]}" = "null" ];then
    rserverCodeList="不在web上下线系统的业务\n无法获取后端IP信息,未探测"
    rserverCodeList=$(echo -e "${rserverCodeList}"|sed 's!^!<b><font color=\\"red\\">!g'|sed 's!$!</font></b></br>!g')
  fi
fi
 
echo \
"{
  \"success\": 1,
  \"header\": [
    \"检测结果\",
    \"架构类型\",
    \"DNS解析记录\",
    \"后端节点探测\",
    \"WEB专区NGINX探测\",
    \"WEB专区LVS探测\",
    \"CDN节点探测\"
  ],
  \"code\": \"002\",
  \"codeData\": {\"username\":[\"${userName}\"]},
  \"templateType\": 1,
  \"values\": [
    [
      \"${checkResultInfo}${errorServerCheck}\",
      \"${architecture}\",
      \"${domainDNSInfo}\",
      \"${rserverCodeList}\",
      \"${nginxCodeList}\",
      \"${lvsCodeList}\",
      \"暂不探测\"
    ]
  ]
}"
rm -f "${temp_file}" "${mail_file}" "${vipInfoFile}"