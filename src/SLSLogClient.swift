//
//  SLSLogClient.swift
//  
//
//  Created by liuweitao on 16/6/15.
//  Copyright © 2016年 珠海三益堂科技有限公司. All rights reserved.
//

import UIKit

//MARK: - 授权信息
class AuthorizeInfo : NSObject {
    //提交日志所需参数
    var Region:String = "cn-qingdao.log.aliyuncs.com"
    var Project = "qingplus"        //项目名称
    var LogStore = "phone_log"   //日志库
    
    var AccessKeyId:String!
    var AccessKeySecret:String!
    
    var accessToken:String!
    var expireDate:NSDate!
}

class LogItem:NSObject {
    
    var time:Int64 = NSDate.returnTimeStampWithCurrentDate() / 1000
    var content:[String:AnyObject] = [:]
    var isSubmit:Int = 1    //0-是 1-否
    
    func pushBack(key:String, value:AnyObject) {
        content[key] = value
    }
    
    func getBack(key:String)->AnyObject? {
        return content[key]
    }
    
    func toDict()->[String:AnyObject] {
        var dict:[String:AnyObject] = [:]
        dict["__time__"] = NSNumber(longLong: time)
        
        for (key, val) in content {
            dict[key] = val
        }
        
        return dict
    }
}

class LogItems:NSObject {
    var topic:String = ""
    var source:String = ""
    var items:[LogItem] = []
    
    func pushBack(item:LogItem) {
        self.items.append(item)
    }
    
    func toDict()->[String:AnyObject] {
        var dict:[String:AnyObject] = [:]
        dict["__topic__"] = topic
        dict["__source__"] = source
        var logs:[[String:AnyObject]] = []
        for item in items {
            logs.append(item.toDict())
        }
        dict["__logs__"] = logs
        return dict
    }
}

//MARK: - 日志Client
/**
    提交日志所需的accessKeyId、accessSecret、accessToken、API入口等信息
    通过设置SLSLogClient.authorizeBlock，在SLSLogClient.authorizeBlock里面通过自己的方式获取到后， 初始化authorizeInfo
    初始化完毕后 主动根据情况调用completeBlock或failedBlock
 
    let client = SLSLogClient.instance;
    client.authorizeBlock = {(authorizeInfo:AuthorizeInfo,completeBlock:dispatch_block_t?,failedBlock:dispatch_block_t?)->Void in
 
        //TODO 通过其他途径获取到相关信息后 例如调用某个接口
        authorizeInfo.AccessKeyId = XXXX
        authorizeInfo.AccessKeySecret = XXX
        authorizeInfo.accessToken = XXX
        authorizeInfo.Project = xxx
        authorizeInfo.LogStore = xxx
        authorizeInfo.Region =  "cn-qingdao.log.aliyuncs.com" (注意region不要包含http[s]://)
 
        if 成功 {
            completeBlock?()
        } else {
            failedBlock?()
        }
    }
 
    //构造日志
    let item = LogItems()
    item.topic = "pv"
    //item.source = "" 来源默认为空
    let log = LogItem()
    log.pushBack("Source", value: "Fitness")
    log.pushBack("Event", value: "BuySomethingFromTaobao")
    log.pushBack("name", value: "哈哈哈 终于提交上来了")
    log.pushBack("IpAddr", value: NSString.getIpAddr())
    item.pushBack(log)
    
    client.postLogItems(item)
 */

typealias AuthorizeBlock = (authorizeInfo:AuthorizeInfo, completeBlock:dispatch_block_t?, failedBlock:dispatch_block_t?)->Void


class SLSLogClient: NSObject {
    
    static let instance:SLSLogClient = SLSLogClient()
    
    var authorizeBlock:AuthorizeBlock?
    
    var authorizeInfo:AuthorizeInfo = AuthorizeInfo()
    
    var apiURL:String {
        get{
            return "http://\(authorizeInfo.Project).\(authorizeInfo.Region)"
        }
    }
    
    var userAgent:String {
        get{
            let execute = (NSBundle.mainBundle().infoDictionary?[String(kCFBundleIdentifierKey)] as? String) ?? ""
            let version = (NSBundle.mainBundle().infoDictionary?[String(kCFBundleVersionKey)] as? String) ?? ""
            let model = UIDevice.currentDevice().model
            let systemVersion = UIDevice.currentDevice().systemVersion
            let scale = String(format: "%0.2f",UIScreen.mainScreen().scale)
            let userAgent = "\(execute)/\(version) (\(model); iOS \(systemVersion); Scale/\(scale))"
            return userAgent
        }
    }
    
    let CommonHeaders:[String:AnyObject] = [
        "x-log-apiversion":"0.6.0"/**API的版本号，当前版本为0.6.0*/,
        "x-log-signaturemethod":"hmac-sha1"/**签名计算方式，目前仅支持”hmac-sha1”。*/
    ]
    
    //MARK: - 提交日志
    func postLogItems(logItems:LogItems) {
        let block:()->Void = {[weak self]()->Void in
            guard let weakSelf = self else {return}
            let method = "POST"
            let url = weakSelf.apiURL+"/logstores/\(weakSelf.authorizeInfo.LogStore)/shards/lb"
            
            let dict = logItems.toDict()
            
            let req = weakSelf.buildRequest(method, url: url, params: dict)
            weakSelf.sendReq(req)
        }
        self.authorize(block, failed:nil)
    }
    
    func sendReq(req:NSURLRequest?) {
        if let req = req {
            self.printReq(req)
            NSURLConnection.sendAsynchronousRequest(req, queue: NSOperationQueue.mainQueue(), completionHandler: { (resp, data, error) -> Void in
                if let resp = resp as? NSHTTPURLResponse {
                    self.printResp(resp)
                    if let data = data {
                        if let dict = SLSLogClient.toJSONObject(data) as? [String:AnyObject] {
                            print(SLSLogClient.toJSONString(dict))
                            
                        }
                    }
                    
                }
            })
        }
    }
    
    //MARK: - 获取授权信息
    /**
     获取提交日志所需的accessKeyId和accessKeySecret
     */
    func authorize(afterAuthorize:dispatch_block_t?, failed:dispatch_block_t?) {
        if self.authorizeInfo.accessToken == nil || self.isTokenExpire() {
            self.authorizeBlock?(authorizeInfo: self.authorizeInfo, completeBlock: afterAuthorize, failedBlock: failed)
        } else {
            afterAuthorize?()
        }
        
    }
    
    //MARK: - 构造请求
    /**
     构造请求
     @param method http请求方法 GET/POST
     @param url
     @param params post请求参数
     */
    func buildRequest(method:String,url:String,params:[String:AnyObject]?)->NSURLRequest? {
        if let URL = NSURL(string: url) {
            
            let req = NSMutableURLRequest(URL: URL)
            req.HTTPMethod = method
            
            //构造公共请求头
            var headers = self.buildCommonHttpHeader(url)
            
            if method == "GET" {
                //暂不支持GET
            } else {
                var bodyJson:String! = nil
                var zipData:NSData! = nil
                var rawData:NSData! = nil
                
                if let params = params {
                    bodyJson = self.classForCoder.toJSONString(params)
                    //压缩请求body
                    rawData = bodyJson.dataUsingEncoding(NSUTF8StringEncoding)!
                    zipData = rawData.sytZip()
                    if zipData != nil {
                        headers["Content-MD5"] = SLSLogClient.getDataMD5(zipData)
                        headers["Content-Type"] = "application/json"
                        headers["Content-Length"] = "\(zipData.length)"
                        headers["x-log-bodyrawsize"] = "\(rawData.length)"
                        headers["x-log-compresstype"] = "deflate"
                    }
                }
                //签名
                headers["Authorization"] = self.getAuthorization(method, header: headers, url: url)
                req.HTTPBody = zipData
            }
            
            //添加请求头
            for (key, val) in headers {
                req.setValue(val as? String, forHTTPHeaderField: key)
            }
            return req
        }
        return nil
        
    }
    
    func buildCommonHttpHeader(url:String)->[String:AnyObject] {
        var headers = self.CommonHeaders
        headers["Date"] = self.classForCoder.getGMTTime()
        headers["User-Agent"] = userAgent
        headers["Host"] = self.getHostIn(url)
        if let token = self.authorizeInfo.accessToken where token != "" {
            headers["x-acs-security-token"] = token
        }
        return headers
    }
    
    //MARK: - 签名
    func getAuthorization(method:String,header:[String:AnyObject],url:String)->String {
        let path = self.getPathIn(url)
        let signString = self.getSignString(method, header: header, path: path)
        let sign = self.sign(signString)
        return "LOG \(self.authorizeInfo.AccessKeyId):\(sign)"
    }
    
    func sign(string:String)->String {
        return SLSLogClient.hmac_sha1(string, key: self.authorizeInfo.AccessKeySecret)
    }
    
    func getSignString(method:String,header:[String:AnyObject],path:String)->String {
        var signStr = "\(method)\n"
        if let md5 = header["Content-MD5"] as? String {
            //有请求体
            let contentType = header["Content-Type"] as! String
            signStr += "\(md5)\n\(contentType)\n"
        } else {
            signStr += "\n\n"
        }
        
        if let date = header["Date"] as? String {
            signStr += "\(date)\n"
        } else {
            signStr += "\(SLSLogClient.getGMTTime())\n"
        }
        
        signStr += "\(self.getCanonicalizedLOGHeaders(header))\n"
        
        signStr += "\(self.getCanonicalizedResource(path))"
        return signStr
    }
    
    func getCanonicalizedLOGHeaders(header:[String:AnyObject])->String {
        //抽取自定义请求头
        var customHeaders:[String:AnyObject] = [:]
        for (key, val) in header {
            if key.hasPrefix("x-log") || key.hasPrefix("x-acs") {
                //                let lowerkey = key.lowercaseString
                customHeaders[key] = val
            }
        }
        
        //key转为小写后 按升序排序
        let allKeys = customHeaders.keys.sort { (key1, key2) -> Bool in
            return key1 < key2
        }
        
        //按key:val\n组合
        var tmp:[String] = []
        for key in allKeys {
            if let val = customHeaders[key] as? String {
                let tmpKey = (key as NSString)
                let tmpVal = (val as NSString)
                
                tmp.append("\(tmpKey):\(tmpVal)")
            }
        }
        let CanonicalizedLOGHeaders = (tmp as NSArray).componentsJoinedByString("\n")
        
        return CanonicalizedLOGHeaders
    }
    
    func getCanonicalizedResource(path:String)->String {
        var ret = path
        if let idx = path.rangeOfString("?") {
            //?之前
            let basePath = path.substringToIndex(idx.startIndex)
            //?之后#之前的查询字符串 以及 #之后的锚点内容(包括#)
            var query = path.substringFromIndex(idx.startIndex.advancedBy(1))
            var anchor = ""
            if let anchorIdx = query.rangeOfString("#") {
                anchor = query.substringFromIndex(anchorIdx.startIndex)
                query = query.substringToIndex(anchorIdx.startIndex)
            }
            //将参数键值对升序排序
            var params:[String] = (query as NSString).componentsSeparatedByString("&")
            params = params.sort({ (param1, param2) -> Bool in
                return param1 < param2
            })
            query = (params as NSArray).componentsJoinedByString("&")
            ret = "\(basePath)?\(query)\(anchor)"
        }
        return ret
    }
    
    //MARK: - MD5 & HMAC_SHA1 & Base64
    class func getStringMD5(text:String)->String {
        let str = text.cStringUsingEncoding(NSUTF8StringEncoding)
        let strLen = CUnsignedInt(text.lengthOfBytesUsingEncoding(NSUTF8StringEncoding))
        let digestLen = Int(CC_MD5_DIGEST_LENGTH)
        let result = UnsafeMutablePointer<CUnsignedChar>.alloc(digestLen)
        CC_MD5(str!, strLen, result)
        
        let hash = NSMutableString()
        for i in 0 ..< digestLen {
            hash.appendFormat("%02X", result[i])
        }
        result.destroy()
        return String(format: hash as String)
    }
    
    class func getDataMD5(data:NSData)->String {
        
        let bytes = data.bytes
        let strLen = CUnsignedInt(data.length)
        let digestLen = Int(CC_MD5_DIGEST_LENGTH)
        let result = UnsafeMutablePointer<CUnsignedChar>.alloc(digestLen)
        CC_MD5(bytes, strLen, result)
        
        let hash = NSMutableString()
        for i in 0 ..< digestLen {
            hash.appendFormat("%02X", result[i])
        }
        result.destroy()
        return String(format: hash as String)
    }
    
    class func hmac_sha1(text:String, key:String)->String {
        
        let keydata =  key.dataUsingEncoding(NSUTF8StringEncoding)!
        let keybytes = keydata.bytes
        let keylen = keydata.length
        
        let textdata = text.dataUsingEncoding(NSUTF8StringEncoding)!
        let textbytes = textdata.bytes
        let textlen = textdata.length
        
        let resultlen = Int(CC_SHA1_DIGEST_LENGTH)
        let result = UnsafeMutablePointer<CUnsignedChar>.alloc(resultlen)
        CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA1), keybytes, keylen, textbytes, textlen, result)
        
        let resultData = NSData(bytes: result, length: resultlen)
        let base64String = resultData.base64EncodedStringWithOptions(NSDataBase64EncodingOptions(rawValue: 0))
        
        result.destroy()
        return base64String
    }
    
    //MARK: - JSON相关
    class func toJSONString(dict:AnyObject)->String? {
        
        var json:String! = nil
        if let data = try? NSJSONSerialization.dataWithJSONObject(dict, options:NSJSONWritingOptions.PrettyPrinted) {
            if let str = String(data: data, encoding: NSUTF8StringEncoding) {
                json = str
            }
        }
        return json
    }
    
    class func toJSONObject(data:NSData?)->AnyObject? {
        if let data = data {
            if let obj = try? NSJSONSerialization.JSONObjectWithData(data, options: NSJSONReadingOptions.AllowFragments) {
                return obj
            }
        }
        return nil
    }
    
    //MARK: - 工具方法
    /**
     获取url中的host部分
     i.e http://www.baidu.com/a/b/c
     则此函数返回  www.baidu.com
     */
    func getHostIn(url:String)->String {
        var host = url
        if let idx = url.rangeOfString("://") {
            host = host.substringFromIndex(idx.startIndex.advancedBy(3))
        }
        if let idx = host.rangeOfString("/") {
            host = host.substringToIndex(idx.startIndex)
        }
        return host;
    }
    
    /**获取url中的path部分
     i.e url ==> http://www.baidu.com:8089/a/b/c?a=c&t=zzz
     则 getHostIn(url:)方法返回 /a/b/c?a=c&t=zzz
     */
    func getPathIn(url:String)->String {
        var path = url
        if let idx = url.rangeOfString("://") {
            path = path.substringFromIndex(idx.startIndex.advancedBy(3))
        }
        if let idx = path.rangeOfString("/") {
            path = path.substringFromIndex(idx.startIndex)
        } else {
            path = ""
        }
        return path
    }
    
    func isTokenExpire()->Bool {
        var expire = false
        if let expireDate = self.authorizeInfo.expireDate {
            //离过期还有15秒就认为过期了
            let result = expireDate.timeIntervalSinceDate(NSDate())
            expire = result <= 15
        }
        return expire
    }
    
    class func getGMTTime()->String {
        /**Mon, 3 Jan 2010 08:33:47 GMT*/
        let date = NSDate()
        let df = NSDateFormatter()
        df.timeZone = NSTimeZone(abbreviation: "GMT+0000")
        df.locale = NSLocale(localeIdentifier: "en_US")
        df.dateFormat = "EEE, d MMM yyyy HH:mm:ss O"
        let str = df.stringFromDate(date)
        return str
    }
    
    class func getStandardTimeForm(time:String)-> NSDate? {
        let df = NSDateFormatter()
        df.timeZone = NSTimeZone(abbreviation: "GMT+0000")
        df.locale = NSLocale(localeIdentifier: "en_US")
        df.dateFormat = "yyyy-MM-dd'T'HH:mm:ssX"
        let date = df.dateFromString(time)
        return date
    }
    
    //MARK: - DEBUG
    func printReq(req:NSURLRequest) {
        #if DEBUG
        let url = req.URL?.absoluteString ?? ""
        let method = req.HTTPMethod ?? ""
        let headers = req.allHTTPHeaderFields ?? [:]
        var infoStr = "\n\n\(method) \(url):\n"
        for (key, val) in headers {
            infoStr += "\(key): \(val)\n"
        }
        
        if let body = req.HTTPBody {
            let unzipData = body.sytUnZip()
            let strBody = String(data: unzipData, encoding: NSUTF8StringEncoding) ?? ""
            infoStr += "\n\(strBody)"
        }
        print(infoStr)
        #endif
    }
    
    func printResp(resp:NSHTTPURLResponse) {
        #if DEBUG
        let url = resp.URL?.absoluteString ?? ""
        let statusCode = resp.statusCode
        let headers = resp.allHeaderFields ?? [:]
        var infoStr = "\n\n\(statusCode)\t\(url):\n"
        for (key, val) in headers {
            infoStr += "\(key): \(val)\n"
        }
        print(infoStr+"\(resp)")
        #endif
    }
}
