# coding=utf-8
import nmap


class NmapScanner:
    def __init__(self, target, ports, arguments):
        self.target = target
        self.arguments = arguments
        self.ports = ports
        self.result = []
        self.ip = ''

        self.instance = {
            'hostname': '',  # 域名或IP
            'host': '',  # 也就是IP
            'hostname_type': '',
            'vendor': '',  # 设备
            'mac': '',
            'ports': [
                # {   # port_info_db
                #     'protocol': '',
                #     'port': '',
                #     'name': '',
                #     'state': '',
                #     'product': '',
                #     'extrainfo': '',
                #     'reason': '',
                #     'version': '',  # 这个版本可能需要额外检测
                #     'conf': '',
                #     'cpe': ''
                # }
            ],
        }

    def _scan(self):
        nm = nmap.PortScanner()
        try:
            nm.scan(hosts=self.target, ports=self.ports, arguments=self.arguments)
        except Exception as e:
            print self.target, e
        return nm

    def run(self):
        nm = self._scan()
        ips = nm.all_hosts()
        if len(ips) == 0:  # 主机不在线
            return self.instance

        ip = ips[0]
        port_info_list = []
        for index, item in enumerate(nm.csv().split('\r\n')):
            if not item or index == 0:
                continue
            info_list = item.split(';')
            port_info_list.append({
                'protocol': info_list[3],
                'port': info_list[4],
                'name': info_list[5],
                'state': info_list[6],
                'product': info_list[7],
                'extrainfo': info_list[8],
                'reason': info_list[9],
                'version': info_list[10],  # 这个版本可能需要额外检测
                'conf': info_list[11],
                'cpe': info_list[12]
            })

        self.instance['ports'] = port_info_list
        asset = nm[ip]
        self.instance['host'] = ip
        self.instance['hostname'] = asset['hostnames'][0]['name']
        self.instance['hostname_type'] = asset['hostnames'][0]['type']
        if 'mac' in asset['addresses'].keys():  # 内网可得，公网不可得
            mac = asset['addresses']['mac']
            self.instance['mac'] = mac
            # print asset['vendor']
            if mac in asset['vendor']:
                self.instance['vendor'] = asset['vendor'][mac]
        return self.instance


if __name__ == '__main__':
    target_val = '172.31.50.195'  # 172.31.50.0/24
    ports_val = '7001, 9200'
    arguments_val = "-sV"
    new_scan = NmapScanner(target_val, ports_val, arguments_val)
    print new_scan.run()
