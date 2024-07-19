# bootcdn-scan
bootcdn投毒专项检测

### 前言
> 2023年4月份，BootCDN的三个关联域名[bootcdn.net,bootcdn.cn,bootcss.com]ICP备案变更为郑州紫田网络科技有限公司
2023年10月，关联域名staticfile.org和staticfile.net被转入河南泉磐网络科技有限公司

### 方案

扫描排查如下几个域名
```
bootcdn.cn
bootcss.com
bootcdn.net
staticfile.net
staticfile.org
```

安装爬虫katana
安装扫描nuclei
```
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
```

bootcdn.yaml
```
id: bootcdn

info:
  name: bootcdn投毒事件
  author: txf
  severity: critical

http:
  - method: GET
    path:
      - "{{BaseURL}}"

    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - 'bootcdn.cn'
          - 'bootcss.com'
          - 'bootcdn.net'
          - 'staticfile.net'
          - 'staticfile.org'
        condition: or

      - type: status
        status:
          - 200
```
爬虫
```
katana -list url_list.txt -em js -o url.txt
nuclei -l url.txt -t bootcdn.yaml
```

### Link
https://www.54yt.net/435.html
