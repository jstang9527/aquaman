#!/bin/bash
API_SERVER='http://172.31.50.177:9777'


check_env(){
	nmap -V &> /dev/null
        if [ $? -ne 0 ];then
		echo -e "\033[31m nmap command not found!\033[0m"
		yum install -y nmap &> /dev/null
	fi
        url=$API_SERVER/test
        curl $API_SERVER/test | egrep '"errno":\s*0' &> /dev/null
 	if [ $? -ne 0 ];then
        	echo -e "\033[31m Failed Connect API Server!\033[0m"
		return
	fi
        echo -e "\033[32m [success]\033[0m \tcheck_env exit."
        
}

# 获取所有实例
get_instance(){
	curl -X GET "$API_SERVER/instance/list?info=$1&page_size=1000&page_no=1" -H "accept: application/json"	
}

# 获取实例检测结果
get_instance_check_result(){
        #检测任务状态
        curl -X GET "$API_SERVER/instance/info?instance_id=$1" -H "accept: application/json" | egrep '"status":\s*"Completed"'
        if [ $? -ne 0 ];then
                echo -e "\033[31m There is no such instance or the instance detection is not completed!\033[0m"
                return
        fi
	curl -X GET "$API_SERVER/service/list?info=$1&page_size=1000&page_no=1" -H "accept: application/json" | egrep -o '"_id":"[0-9a-zA-Z]{24}' | awk -F:\" '{print $2}' | xargs echo > temp.txt
        num=`wc temp.txt | awk '{print $2}'`
        for i in `seq 1 $num`					 # 根据文件列数进行循环
	do
        	info=`awk -v a=$i  '{print $a}' temp.txt`	 # 打印每一列的内容，-v 参数可以指定一个变量保存外部变量的值，将外部变量传递给awk
                curl -X GET "$API_SERVER/service/info?portinfo_id=$info" -H "accept: application/json"
	done
}

#全自动任务提交
auto_task(){
        echo -e "\033[32m 批量检测/单目标检测\033[0m"
        read -p "Please input scan host or network(example:172.31.50.0/24):" host
        nmap -sn $host | grep "Nmap scan report for" >/dev/null &>/dev/null
        [ $? -ne 0 ] && echo "host $host is down." && return
        nmap -sn $host  | grep "Nmap scan report for" | awk '{print $5}' > host.txt
        while read uphost
		do
			#echo "host $uphost is up."
                        portinfo_id=`curl -X POST "$API_SERVER/instance/info" -H "accept: application/json" -H "Content-Type: application/json" -d "{ \"name\": \"$uphost\", \"port_list\": [], \"target\": \"$uphost\"}" | egrep -o [0-9a-zA-Z]{24}`
                        curl -X PATCH "$API_SERVER/instance/info" -H "accept: application/json" -H "Content-Type: application/json" -d "{ \"instance_id\": \"$portinfo_id\", \"scan_type\": \"vul\"}"
		done<host.txt
}

show_menu(){
	echo "####################################################################################" 
        echo "#                                     Mars shell                                   #"
        echo "#----------------------------------------------------------------------------------#"
        echo "# 0.退出程序                 1.Env check            2.获取所有检测结果(关键词筛选) #"
        echo "# 3.获取实例检测结果         4.全自动漏洞检测                                      #" 
	echo "# 其余功能API 操作文档 $API_SERVER/swagger                           #"
        echo "# Web 客户端地址 http://172.31.50.254:9527                                         #" 
        echo "####################################################################################"
}

while :
do
  clear
  show_menu
  read -p "Input your option:" option
  case $option in
    0) echo -e "\033[32m [Finish]\033[0m \tprogram exit."
       break
    ;;
    1) echo -e "\033[32m Starting env check......\033[0m"
       check_env
    ;;
    2) echo -e "\033[32m 获取所有实例\033[0m"
       read -p "输入模糊查询(根据实例名)的关键词:" info
       get_instance $info
    ;;
    3) echo -e "\033[32m 获取实例检测结果\033[0m"
       read -p "输入实例ID:" instance_id
       get_instance_check_result $instance_id
    ;;
    4) echo -e "\033[32m [start]\033[0m \t全自动检测"
       auto_task
    ;;
    *) echo -e "\033[31m [Error]\033[0m \tOption not in items!"
  esac
  read -p "Input <enter> to continue..."
done
