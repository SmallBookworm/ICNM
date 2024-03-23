package com.icnm.util;

import lombok.Getter;
import lombok.Setter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.snmp4j.*;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.*;
import org.snmp4j.security.*;
import org.snmp4j.smi.*;
import org.snmp4j.transport.DefaultUdpTransportMapping;
import org.snmp4j.util.PDUFactory;
import org.snmp4j.util.TableEvent;
import org.snmp4j.util.TableUtils;

import java.io.IOException;
import java.util.*;


public class SnmpUtil {

    private static Logger log = LoggerFactory.getLogger(SnmpUtil.class);
    private static Snmp snmp   = null;

    private static final int COLON_SIZE = 16;
    //传入要查询的Snmp版本
    @Setter
    @Getter
    private int version;
    //传入要查询的主机ip
    @Setter
    @Getter
    private String hostIp;
    //传入要查询的端口号
    @Setter
    @Getter
    private String hostPort;
    //传入要查询的团体名
    @Setter
    @Getter
    private String community ;
    //接收要查询的oids, for snmpGet and snmpWalk
    @Setter
    @Getter
    private String oid;

    private String addressGet ;

    //获取设备描述信息
    private String healthOID1 = "1.3.6.1.4.1";
    //设备电源状态
    String healthOID2 = "1.3.6.1.";
    //获取系统温度
    private String healthOID3 = "1.3.6.";

    public SnmpUtil(String hostIp, String hostPort, String snmpCommunity, int version){
        this.setHostIp(hostIp);
        this.setHostPort(hostPort);
        this.setCommunity(snmpCommunity);
        this.setVersion(version);
    }

    public void  initSnmp() throws IOException {
        //1、初始化多线程消息转发类
        MessageDispatcher messageDispatcher = new MessageDispatcherImpl();
        //其中要增加三种处理模型。如果snmp初始化使用的是Snmp(TransportMapping<? extends Address> transportMapping) ,就不需要增加
        messageDispatcher.addMessageProcessingModel(new MPv1());
        messageDispatcher.addMessageProcessingModel(new MPv2c());
        //当要支持snmpV3版本时，需要配置user
        OctetString localEngineID = new OctetString(MPv3.createLocalEngineID());
        USM usm = new USM(SecurityProtocols.getInstance().addDefaultProtocols(), localEngineID, 0);
        UsmUser user = new UsmUser(new OctetString("SNMPV3"), AuthSHA.ID, new OctetString("authPassword"),
                PrivAES128.ID, new OctetString("privPassword"));
        usm.addUser(user.getSecurityName(), user);
        messageDispatcher.addMessageProcessingModel(new MPv3(usm));
        //2、创建transportMapping
        TransportMapping<?> transportMapping = new DefaultUdpTransportMapping();
        //3、正式创建snmp
        snmp = new Snmp(messageDispatcher, transportMapping);
        //开启监听
        snmp.listen();
    }

    private  Target createTarget() {
        //先得到连接的ip和端口号
        this.addressGet = "udp:" + this.getHostIp()+"/"+this.getHostPort();

        Target target = null;
        int version = this.version;
        if (!(version == SnmpConstants.version3 || version == SnmpConstants.version2c || version == SnmpConstants.version1)) {
            log.error("参数version异常");
            return target;
        }
        if (version == SnmpConstants.version3) {
            target = new UserTarget();
            //snmpV3需要设置安全级别和安全名称，其中安全名称是创建snmp指定user设置的new OctetString("SNMPV3")
            target.setSecurityLevel(SecurityLevel.AUTH_PRIV);
            target.setSecurityName(new OctetString("SNMPV3"));
        } else
        {
            //snmpV1和snmpV2需要指定团体名名称
            target = new CommunityTarget();
            ((CommunityTarget) target).setCommunity(new OctetString(this.community));
            if (version == SnmpConstants.version2c) {
                target.setSecurityModel(SecurityModel.SECURITY_MODEL_SNMPv2c);
            }
        }
        target.setVersion(version);
        //必须指定，没有设置就会报错。
        target.setAddress(GenericAddress.parse(this.addressGet));
        target.setRetries(2);
        target.setTimeout(8000);
        return target;
    }

    private static PDU createPDU(int version, int type, String oid) {
        PDU pdu = null;
        if (version == SnmpConstants.version3) {
            pdu = new ScopedPDU();
        } else {
            pdu = new PDUv1();
        }
        pdu.setType(type);
        //可以添加多个变量oid
        /*for(String oid:oids){
            pdu.add(new VariableBinding(new OID(oid)));
        }*/
        pdu.add(new VariableBinding(new OID(oid)));
        return pdu;
    }



    /**
     * WALK方式请求
     *功能简介：这个方法是getnext，就是遍历该oid下的所有子节点
     */
    public List<Map<String,Object>> snmpWalk() {
        try {

            List<Map<String,Object>> list = new ArrayList<>();

            //1、初始化snmp,并开启监听
            initSnmp();
            //2、创建目标对象
            Target target = createTarget();
            //3、创建报文
            PDU pdu = createPDU(this.version, PDU.GETNEXT, this.oid);
            //4、发送报文，并获取返回结果
            boolean matched = true;
            while (matched) {
                ResponseEvent responseEvent = snmp.send(pdu, target);
                if (responseEvent == null || responseEvent.getResponse() == null) {
                    //LogUtil.info("snmp TimeOut...");
                    break;
                }
                PDU response = responseEvent.getResponse();
                String nextOid = null;
                Vector<? extends VariableBinding> variableBindings = response.getVariableBindings();
                for (int i = 0; i < variableBindings.size(); i++) {

                    VariableBinding variableBinding = variableBindings.elementAt(i);
                    Variable variable = variableBinding.getVariable();
                    nextOid = variableBinding.getOid().toDottedString();
                    //如果不是这个节点下的oid则终止遍历，否则会输出很多，直到整个遍历完。
                    if (!nextOid.startsWith(oid)) {
                        matched = false;
                        break;
                    }
                    Map<String,Object> map = new HashMap();
                    //放入oid以及oid对应获得的值
                    map.put(nextOid,variable);
                    list.add(map);
                }
                if (!matched) {
                    break;
                }
                pdu.clear();
                pdu.add(new VariableBinding(new OID(nextOid)));
            }

            System.out.println("list的大小 = " +list.size());
            return list;

        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;
    }


    /**
     * 功能简介：获取单个节点oid对应的值
     * @throws IOException
     */
    public  void snmpGet( ) throws IOException {


        try {

            //1、初始化snmp,并开启监听
            initSnmp();
            //2、创建目标对象
            Target target = createTarget();
            //3、创建报文
            PDU pdu = createPDU(this.version, PDU.GET, this.oid);
            //4、发送报文，并获取返回结果


            ResponseEvent responseEvent = snmp.send(pdu, target);
            PDU response = responseEvent.getResponse();

            if (response == null) {
                System.out.println("response is null, request time out");
            } else {

                System.out.println("response pdu size is " + response.size());
                for (int i = 0; i < response.size(); i++) {
                    VariableBinding vb = response.get(i);
                    System.out.println(vb.getOid() + " = " + vb.getVariable());
                }

            }
            System.out.println("SNMP GET one OID value finished !");
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("SNMP Get Exception:" + e);
        } finally {
            if (snmp != null) {
                try {
                    snmp.close();
                } catch (IOException ex1) {
                    snmp = null;
                }
            }

        }
    }
    public List<TableEvent> getTable(Target target, String[] oids){

        TableUtils tableUtils = new TableUtils(snmp, new PDUFactory() {
            @Override
            public PDU createPDU(MessageProcessingModel messageProcessingModel) {
                return null;
            }

            @Override
            public PDU createPDU(Target arg0) {
                PDU request = new PDU();
                request.setType(PDU.GET);
                return request;
            }
        });
        OID[] columns = new OID[oids.length];
        for (int i = 0; i < oids.length; i++)
            columns[i] = new OID(oids[i]);

        return tableUtils.getTable(target, columns, null, null);
    }
    //host
    //获取cpu使用率
    public void collectCPU() {

        String[] oids = {"1.3.6.1.2.1.25.3.3.1.2"};
        try {
            //1、初始化snmp,并开启监听
            initSnmp();
            //2、创建目标对象
            Target target = createTarget();

            List<TableEvent> list = this.getTable(target,oids);
            if(list.size()==1 && list.get(0).getColumns()==null){
                System.out.println(" null");
            }else{
                int percentage = 0;
                for(TableEvent event : list){
                    VariableBinding[] values = event.getColumns();
                    if(values != null){
                        percentage += Integer.parseInt(values[0].getVariable().toString());
                    }
                }
                System.out.println("CPU利用率为："+percentage/list.size()+"%");
            }
        } catch(Exception e){
            e.printStackTrace();
        }finally{
            try {

                if(snmp!=null)
                    snmp.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }


    //获取内存相关信息
    public void collectMemory() {

        String[] oids = {"1.3.6.1.2.1.25.2.3.1.2",  //type 存储单元类型
                "1.3.6.1.2.1.25.2.3.1.3",  //descr
                "1.3.6.1.2.1.25.2.3.1.4",  //unit 存储单元大小
                "1.3.6.1.2.1.25.2.3.1.5",  //size 总存储单元数
                "1.3.6.1.2.1.25.2.3.1.6"}; //used 使用存储单元数;
        String PHYSICAL_MEMORY_OID = "1.3.6.1.2.1.25.2.1.2";//物理存储
        String VIRTUAL_MEMORY_OID = "1.3.6.1.2.1.25.2.1.3"; //虚拟存储
        try {
            //1、初始化snmp,并开启监听
            initSnmp();
            //2、创建目标对象
            Target target = createTarget();

            @SuppressWarnings("unchecked")
            List<TableEvent> list = this.getTable(target,oids);
            if(list.size()==1 && list.get(0).getColumns()==null){
                System.out.println(" null");
            }else{
                for(TableEvent event : list){
                    VariableBinding[] values = event.getColumns();
                    if(values == null) continue;
                    int unit = Integer.parseInt(values[2].getVariable().toString());//unit 存储单元大小
                    int totalSize = Integer.parseInt(values[3].getVariable().toString());//size 总存储单元数
                    int usedSize = Integer.parseInt(values[4].getVariable().toString());//used  使用存储单元数
                    String oid = values[0].getVariable().toString();
                    if (PHYSICAL_MEMORY_OID.equals(oid)){
                        System.out.println("PHYSICAL_MEMORY----->物理内存大小："+(long)totalSize * unit/(1024*1024*1024)+"G   内存使用率为："+(long)usedSize*100/totalSize+"%");
                    }else if (VIRTUAL_MEMORY_OID.equals(oid)) {
                        System.out.println("VIRTUAL_MEMORY----->虚拟内存大小："+(long)totalSize * unit/(1024*1024*1024)+"G   内存使用率为："+(long)usedSize*100/totalSize+"%");
                    }
                }
            }
        } catch(Exception e){
            e.printStackTrace();
        }finally{
            try {
                if(snmp!=null)
                    snmp.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    //获取磁盘相关信息
    public  void collectDisk() {

        String DISK_OID = "1.3.6.1.2.1.25.2.1.4";
        String[] oids = {"1.3.6.1.2.1.25.2.3.1.2",  //type 存储单元类型
                "1.3.6.1.2.1.25.2.3.1.3",  //descr
                "1.3.6.1.2.1.25.2.3.1.4",  //unit 存储单元大小
                "1.3.6.1.2.1.25.2.3.1.5",  //size 总存储单元数
                "1.3.6.1.2.1.25.2.3.1.6"}; //used 使用存储单元数;
        try {
            //1、初始化snmp,并开启监听
            initSnmp();
            //2、创建目标对象
            Target target = createTarget();

            @SuppressWarnings("unchecked")
            List<TableEvent> list = this.getTable(target,oids);
            if(list.size()==1 && list.get(0).getColumns()==null){
                System.out.println(" null");
            }else{
                for(TableEvent event : list){
                    VariableBinding[] values = event.getColumns();
                    if(values == null ||!DISK_OID.equals(values[0].getVariable().toString()))
                        continue;
                    int unit = Integer.parseInt(values[2].getVariable().toString());//unit 存储单元大小
                    int totalSize = Integer.parseInt(values[3].getVariable().toString());//size 总存储单元数
                    int usedSize = Integer.parseInt(values[4].getVariable().toString());//used  使用存储单元数
                    System.out.println(getChinese(values[1].getVariable().toString())+"   磁盘大小："+(long)totalSize*unit/(1024*1024*1024)+"G   磁盘使用率为："+(long)usedSize*100/totalSize+"%");
                }
            }
        } catch(Exception e){
            e.printStackTrace();
        }finally{
            try {

                if(snmp!=null)
                    snmp.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }


    //服务器进程集合信息
    public void collectProcess() {

        String[] oids =
                {"1.3.6.1.2.1.25.4.2.1.1",  //index
                        "1.3.6.1.2.1.25.4.2.1.2",  //name
                        "1.3.6.1.2.1.25.4.2.1.4",  //run path
                        "1.3.6.1.2.1.25.4.2.1.6",  //type
                        "1.3.6.1.2.1.25.5.1.1.1",  //cpu
                        "1.3.6.1.2.1.25.5.1.1.2"}; //memory
        try {
            //1、初始化snmp,并开启监听
            initSnmp();
            //2、创建目标对象
            Target target = createTarget();

            @SuppressWarnings("unchecked")
            List<TableEvent> list = this.getTable(target,oids);
            if(list.size()==1 && list.get(0).getColumns()==null){
                System.out.println(" null");
            }else{
                for(TableEvent event : list){
                    VariableBinding[] values = event.getColumns();
                    if(values == null) continue;
                    String name = values[1].getVariable().toString();//name
                    String cpu = values[4].getVariable().toString();//cpu
                    String memory = values[5].getVariable().toString();//memory
                    String path = values[2].getVariable().toString();//path
                    System.out.println("name--->"+name+"  cpu--->"+cpu+"  memory--->"+memory+"  path--->"+getChinese(path,"utf-8"));
                }
            }
        } catch(Exception e){
            e.printStackTrace();
        }finally{
            try {
                if(snmp!=null)
                    snmp.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    //服务器系统服务集合
    public void collectService() {

        String[] oids =
                {"1.3.6.1.4.1.77.1.2.3.1.1"};
        try {
            //1、初始化snmp,并开启监听
            initSnmp();
            //2、创建目标对象
            Target target = createTarget();


            List<TableEvent> list = this.getTable(target,oids);
            if(list.size()==1 && list.get(0).getColumns()==null){
                System.out.println(" null");
            }else{
                for(TableEvent event : list){
                    VariableBinding[] values = event.getColumns();
                    if(values == null) continue;
                    String name = values[0].getVariable().toString();//name
                    System.out.println("名称--->"+getChinese(name,"utf-8"));//中文乱码，需要转为utf-8编码
                }
            }
        } catch(Exception e){
            e.printStackTrace();
        }finally{
            try {
                if(snmp!=null)
                    snmp.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    //服务器接口集合
    public void collectInterface() {

        String[] IF_OIDS =
                {"1.3.6.1.2.1.2.2.1.1",  //Index
                        "1.3.6.1.2.1.2.2.1.2",  //descr
                        "1.3.6.1.2.1.2.2.1.3",  //type
                        "1.3.6.1.2.1.2.2.1.5",  //speed
                        "1.3.6.1.2.1.2.2.1.6",  //mac
                        "1.3.6.1.2.1.2.2.1.7",  //adminStatus
                        "1.3.6.1.2.1.2.2.1.8",  //operStatus

                        "1.3.6.1.2.1.2.2.1.10", //inOctets
                        "1.3.6.1.2.1.2.2.1.16", //outOctets
                        "1.3.6.1.2.1.2.2.1.14", //inError
                        "1.3.6.1.2.1.2.2.1.20", //outError
                        "1.3.6.1.2.1.2.2.1.13", //inDiscard
                        "1.3.6.1.2.1.2.2.1.19", //outDiscard
                        "1.3.6.1.2.1.2.2.1.11", //inUcastPkts
                        "1.3.6.1.2.1.2.2.1.17", //outUcastPkts
                        "1.3.6.1.2.1.2.2.1.12", //inNUcastPkts
                        "1.3.6.1.2.1.2.2.1.18"};//outNUcastPkts
        String[] IP_OIDS =
                {"1.3.6.1.2.1.4.20.1.1", //ipAdEntAddr
                        "1.3.6.1.2.1.4.20.1.2", //ipAdEntIfIndex
                        "1.3.6.1.2.1.4.20.1.3"};//ipAdEntNetMask
        try {
            //1、初始化snmp,并开启监听
            initSnmp();
            //2、创建目标对象
            Target target = createTarget();

            List<TableEvent> list = this.getTable(target,IF_OIDS);
            if(list.size()==1 && list.get(0).getColumns()==null){
                System.out.println(" null");
            }else{
                for(TableEvent event : list){
                    VariableBinding[] values = event.getColumns();
                    if(values == null) continue;
                    System.out.println("interface ---Index："+values[0].getVariable().toString()+"  descr："+getChinese(values[1].getVariable().toString())+"  type："+values[2].getVariable().toString()+" speed："+values[3].getVariable().toString()+" mac："+getChinese(values[4].getVariable().toString())+" adminStatus："+values[5].getVariable().toString()+"  operStatus："+values[6].getVariable().toString());
                }
            }
//获取ip

            List<TableEvent> iplist = this.getTable(target,IP_OIDS);
            if(iplist.size()==1 && iplist.get(0).getColumns()==null){
                System.out.println(" null");
            }else{
                for(TableEvent event : iplist){
                    VariableBinding[] values = event.getColumns();
                    if(values == null) continue;
                    System.out.println(" IP--->ipAdEntAddr:"+values[0].getVariable().toString()+"   ipAdEntIfIndex:"+values[1].getVariable().toString()+"   ipAdEntNetMask:"+values[2].getVariable().toString());
                }
            }
        } catch(Exception e){
            e.printStackTrace();
        }finally{
            try {
                if(snmp!=null)
                    snmp.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    //服务器端口集合
    public void collectPort() {

        String[] TCP_CONN = {"1.3.6.1.2.1.6.13.1.1", //status
                "1.3.6.1.2.1.6.13.1.3"}; //port

        String[] UDP_CONN = {"1.3.6.1.2.1.7.5.1.2"};
        try {
            //1、初始化snmp,并开启监听
            initSnmp();
            //2、创建目标对象
            Target target = createTarget();
//获取TCP 端口
            List<TableEvent> list = this.getTable(target,TCP_CONN);
            if(list.size()==1 && list.get(0).getColumns()==null){
                System.out.println(" null");
            }else{
                for(TableEvent event : list){
                    VariableBinding[] values = event.getColumns();
                    if(values == null) continue;
                    int status = Integer.parseInt(values[0].getVariable().toString());
                    System.out.println("status--->"+status+"   TCP_port--->"+values[1].getVariable().toString());
                }
            }
//获取udp 端口

            List<TableEvent> udplist = this.getTable(target,UDP_CONN);
            if(udplist.size()==1 && udplist.get(0).getColumns()==null){
                System.out.println(" null");
            }else{
                for(TableEvent event : udplist){
                    VariableBinding[] values = event.getColumns();
                    if(values == null) continue;
                    String name = values[0].getVariable().toString();//name
                    System.out.println("UDP_port--->"+name);
                }
            }
        } catch(Exception e){
            e.printStackTrace();
        }finally{
            try {
                if(snmp!=null)
                    snmp.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    //服务器安装软件集合
    public void collectSoft() {

        String[] oids =
                {	"1.3.6.1.2.1.25.6.3.1.2",  //software
                        "1.3.6.1.2.1.25.6.3.1.4",  //type
                        "1.3.6.1.2.1.25.6.3.1.5"}; //install date
        try {
            //1、初始化snmp,并开启监听
            initSnmp();
            //2、创建目标对象
            Target target = createTarget();

            List<TableEvent> list = this.getTable(target,oids);
            if(list.size()==1 && list.get(0).getColumns()==null){
                System.out.println(" null");
            }else{
                for(TableEvent event : list){
                    VariableBinding[] values = event.getColumns();
                    if(values == null) continue;
                    String software = values[0].getVariable().toString();//software
                    String type = values[1].getVariable().toString();//type
                    String date = values[2].getVariable().toString();//date
                    System.out.println("软件名称--->"+getChinese(software)+"  type--->"+type+"  安装时间--->"+hexToDateTime(date.replace("'", "")));
                }
            }
        } catch(Exception e){
            e.printStackTrace();
        }finally{
            try {
                if(snmp!=null)
                    snmp.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }


    /**
     * 获取磁盘的中文名字
     * 解决snmp4j中文乱码问题
     */
    public static String getChinese(String octetString){
        return getChinese(octetString,null);
    }
    public static String getChinese(String octetString,String charsetEncoding){
        if(octetString == null || "".equals(octetString)
                || "null".equalsIgnoreCase(octetString)) return "";
        try{
            String[] temps = octetString.split(":");
            if(temps.length < COLON_SIZE)
                return octetString;
            byte[] bs = new byte[temps.length];
            for(int i=0;i<temps.length;i++)
                bs[i] = (byte)Integer.parseInt(temps[i],16);
            if(charsetEncoding == null || charsetEncoding.equals("")){
                charsetEncoding = "GBK";
            }
            return new String(bs,charsetEncoding);
        }catch(Exception e){
            return null;
        }
    }
    /**
     * 将16进制的时间转换成标准的时间格式
     */
    private static String hexToDateTime(String hexString) {
        if(hexString == null || "".equals(hexString))
            return "";
        String dateTime = "";
        try {
            byte[] values = OctetString.fromHexString(hexString).getValue();
            int year, month, day, hour, minute;

            year = values[0] * 256 + 256 + values[1];
            month = values[2];
            day = values[3];
            hour = values[4];
            minute = values[5];

            char format_str[] = new char[22];
            int index = 3;
            int temp = year;
            for (; index >= 0; index--) {
                format_str[index] = (char) (48 + (temp - temp / 10 * 10));
                temp /= 10;
            }
            format_str[4] = '-';
            index = 6;
            temp = month;
            for (; index >= 5; index--) {
                format_str[index] = (char) (48 + (temp - temp / 10 * 10));
                temp /= 10;
            }
            format_str[7] = '-';
            index = 9;
            temp = day;
            for (; index >= 8; index--) {
                format_str[index] = (char) (48 + (temp - temp / 10 * 10));
                temp /= 10;
            }
            format_str[10] = ' ';
            index = 12;
            temp = hour;
            for (; index >= 11; index--) {
                format_str[index] = (char) (48 + (temp - temp / 10 * 10));
                temp /= 10;
            }
            format_str[13] = ':';
            index = 15;
            temp = minute;
            for (; index >= 14; index--) {
                format_str[index] = (char) (48 + (temp - temp / 10 * 10));
                temp /= 10;
            }
            dateTime = new String(format_str,0,format_str.length).substring(0, 16);
        } catch (Exception e) {
//LogFactory.getLog(getClass()).error(e);
        }
        return dateTime;
    }

    //开启监控的main方法。
    public static void main(String[] args) throws IOException {


        SnmpUtil mySnmpUtil = new SnmpUtil("127.0.0.1","161","public",SnmpConstants.version2c);
        mySnmpUtil.setOid("1.3.6.1.2.1.1.1.0");
        mySnmpUtil.snmpGet();
        mySnmpUtil.setOid("1.3.6.1.2.1.1");
        mySnmpUtil.snmpWalk();
//        mySnmpUtil.collectCPU();        System.out.println(System.lineSeparator());
//        mySnmpUtil.collectMemory();        System.out.println(System.lineSeparator());
//        mySnmpUtil.collectDisk();        System.out.println(System.lineSeparator());
        mySnmpUtil.collectProcess();        System.out.println(System.lineSeparator());
//        mySnmpUtil.collectService();        System.out.println(System.lineSeparator());
//        mySnmpUtil.collectInterface();        System.out.println(System.lineSeparator());
//        mySnmpUtil.collectPort();        System.out.println(System.lineSeparator());
//        mySnmpUtil.collectSoft();

//下面这个方法需要有子节点，遍历子节点然后从子节点中拿数据，这里是找华为的实体索引
//        SnmpUtil mySnmpUtil = new SnmpUtil("127.0.0.1","161","tuantiming","1.3.6.1.2.1.47.1.1.1.1.5");
//        List<Map<String, Object>> mapList = mySnmpUtil.snmpWalk();
//        Map<String,Integer> result = new HashMap<String,Integer>();
//        int flat= 0;
//        List<String> resultNeed = new ArrayList<>();
//        for (Map<String, Object> map: mapList){
//            for (String key:map.keySet()){
//                System.out.println("key= "+key +" value= "+ map.get(key));
//                //华为
//                if (String.valueOf(map.get(key)).equals("9")){
//                    String substring = key.substring(25, key.length());
//                    resultNeed.add(substring);
//                    System.out.println("找到我需要的数据了"+substring+"9");
//                    break;
//                }
//
//            }
//        }
//        System.out.println("这是我需要的数据"+resultNeed.get(0));

    }
}
