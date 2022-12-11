package com.clearwood.sentry;
 
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.http.*;
import java.time.LocalDateTime;
import java.util.concurrent.TimeUnit;
import org.json.JSONObject;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.Executors;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.ProxySelector;
import java.net.URI;
import org.apache.commons.net.util.SubnetUtils;
import java.io.IOException;
import java.nio.file.Paths;
import java.nio.file.Path;
import java.io.File;
import java.nio.file.Files;
import org.apache.commons.codec.digest.*;

 
public class App2 {

    static final String PCAP_ENDPOINT = "https://save-pcap-7ffm66njka-uc.a.run.app";
    static final String HEARTBEAT_ENDPOINT = "https://us-central1-clearwood-199118.cloudfunctions.net/report-1";
    static final String ERROR_ENDPOINT = "https://us-central1-clearwood-199118.cloudfunctions.net/report-1";
	static Heartbeat heartbeat = new Heartbeat();
    static long pcapUploadDelay = 30L; //Delay between capture and upload in sec
    static long heartbeatInterval = 10L; //Server heartbeat interval in sec
    static String deviceIp;
    static String deviceMac;
    static String gatewayIp;
    static String subnet;
    static String subnetCIDR;
    static String netmask;
    static String iface;
    static String dnsServerIp;
    static String gatewayMac;
    static String broadcast;
    static String dhcpServerIp;
    static LocalDateTime nextSend = null;
    static LocalDateTime lastCapture = null; //timestamp of last captured packets 

/**************************************************************
 * MAIN
 *************************************************************/
	public static void main(String[] args) {
        getNetstat();
        getIp();
        getMac(deviceIp);
        getDNSserver();
        getGatewayMac();
        getDhcpServerIp();

        try {
            Path path = Paths.get("hashes");
            if (Files.notExists(path)) {
                Files.createDirectories(path);
            }
            path = Paths.get("captures");
            if (Files.notExists(path)) {
                Files.createDirectories(path);
            }
        } catch (Exception e) {
            addToErrorLog("ERROR creating capture and/or hash folder", e);
        }

		//start heartbeat
		ScheduledExecutorService es = Executors.newSingleThreadScheduledExecutor();
		es.scheduleAtFixedRate(heartbeat, 0, 1, TimeUnit.MINUTES);

        //start TCPdump
		tcpDump();
	}

/**************************************************************
 * UPLOAD ERRORS TO ENDPOINT
 *************************************************************/
    private static void addToErrorLog(String errorMsg, Exception e) {
        JSONObject jo = new JSONObject();
        errorMsg += ": ";
        if (e != null) {
            errorMsg += " msg: " + e.getMessage() + " trace: " + e.getStackTrace();
        }
        jo.put(LocalDateTime.now().toString(), errorMsg);
    }

/**************************************************************
 * CAPTURE AND UPLOAD PCAP 
 *************************************************************/
    //use TCPdump to capture incoming packets to pcap files
    //limit to traffic directed at this device
    //and avoid capturing normal DHCP and ARP traffic
    //save to 5 files in round robin  
	private static void tcpDump() {
        //TCPdump options
        String captureFilter =  " src net " + subnetCIDR + " and dst host " + deviceIp + 
        " and host not " + gatewayIp + " and host not " + dhcpServerIp + " and not ether broadcast";
        if (!gatewayIp.contains(dnsServerIp)) {
            captureFilter += " and host not " + dnsServerIp;
        }
        String tcpDumpCmd = "echo '' | sudo -S tcpdump -l -i " + iface + captureFilter + " -nn -U --print -C 1 -W 10 -w ~/Code/sentry/captures/cap.pcap";
        System.out.println(tcpDumpCmd);
        //run TCPdump
        ProcessBuilder processBuilder = null;
        processBuilder = new ProcessBuilder("/bin/bash", "-c", tcpDumpCmd);
        try {
            Process process = processBuilder.start();
            BufferedReader stdInput = new BufferedReader(new InputStreamReader(process.getInputStream()));
            //BufferedReader stdError = new BufferedReader(new InputStreamReader(process.getErrorStream()));
            String s = null;
            while (true) {
                if ((s = stdInput.readLine()) != null) {
                    //upload is triggered by heartbeat thread 
                    lastCapture = LocalDateTime.now();
                    nextSend = lastCapture.plusSeconds(pcapUploadDelay);
                } 
                /* TODO implement error handling
                if ((s = stdError.readLine()) != null) {
                    App2.postQueue.add("err:" + s);
                }
                */
            }
        } catch (Exception e) {
            addToErrorLog("ERROR Executing tcpdump command", e);
        }
	}
    //upload pcap all files that have not yet been uploaded to endpoint
    //triggered by heartbeat thread
    public static void uploadCaptures() throws IOException {
        try {   
            //iterate through hashes of uploaded files
            File dir = new File("captures");
            File[] directoryListing = dir.listFiles();
            for (File capture : directoryListing) {
            if (!uploaded(capture)) {
                uploadPcap(capture);
            }
            }
        } catch (Exception e) {
            addToErrorLog("ERROR uploading captures", e);
        }
    }
    //execute the upload
    public static void uploadPcap(File file) throws IOException {
        try {   
            HttpRequest request = HttpRequest.newBuilder()
            .uri(new URI(PCAP_ENDPOINT))
            .headers("Content-Type", "application/octet-stream")
            .POST(HttpRequest.BodyPublishers.ofFile(
                Paths.get(file.getPath())))
            .build(); 
            HttpResponse<String> response = HttpClient
            .newBuilder()
            .proxy(ProxySelector.getDefault())
            .build()
            .send(request, HttpResponse.BodyHandlers.ofString());
            //System.out.println("sent file code: " + response.statusCode() +  " " + file.getName());
            //System.out.println("response: " + response.body());
            if (response.statusCode() != 200) {
                addToErrorLog("ERROR uploading PCAP HTTP code: " + response.statusCode(), null);
            } else {
                //record hash by creating a file named with the hash
                createHashFile(md5hash(file));
            }
        } catch (Exception e) {
            addToErrorLog("ERROR sending PCAP data", e);
        }
    }
    //check hash to confirm if the pcap file not already been uploaded to the server 
    public static boolean uploaded(File candidate) {
        boolean uploaded = false;
        try {
            String candidateHash = md5hash(candidate);
            //iterate through existing files that have hashes as their names
            File dir = new File("hashes");
            File[] directoryListing = dir.listFiles();
            if (directoryListing != null) {
              for (File hash : directoryListing) {
                if (hash.getName().contains(candidateHash)) {
                    uploaded = true;
                }
              }
            } 
        } catch (Exception e) {
            addToErrorLog("ERROR checking if file has been uploaded", e);
        }
        return uploaded;
    }
    public static String md5hash(File f) {
        String md5Hex = "";
        try {
            byte[] arr = Files.readAllBytes(f.toPath());
            md5Hex = DigestUtils.md5Hex(arr).toUpperCase();
        } catch (Exception e) {
            addToErrorLog("ERROR hashing file", e);
        }
        return md5Hex;
    }
    //store the hashes of uploaded files as filenames in the hahses folder 
    static void createHashFile(String filename) {
        try {
            Path path = Paths.get("hashes");
            if (Files.notExists(path)) {
                Files.createDirectories(path);
            }
            File myObj = new File("hashes/" + filename);
            if (myObj.createNewFile()) {
                //System.out.println("hash file created: " + myObj.getName());
            } else {
                //System.out.println("hash file already exists.");
            }
        } catch (IOException e) {
            addToErrorLog("An error occurred creating the hash file", e);
        }
    }




/**************************************************************
 * SCHEDULED UPLOAD OF HEARTBEATS / PCAP FILES / ERROR LOGS 
 *************************************************************/
    private static class Heartbeat implements Runnable {
        @Override
        public void run() {
            //-------------------------------------
            // send heartbeat
            //-------------------------------------
            try {
                JSONObject jo = new JSONObject();

                jo.put("heartbeat", LocalDateTime.now().toString());
                JSONObject joWrapper = new JSONObject();
                joWrapper.put(deviceMac, jo);

                String json = jo.toString();
                HttpRequest request = HttpRequest.newBuilder()
                .uri(new URI(HEARTBEAT_ENDPOINT))
                .headers("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json))
                .build();

                HttpResponse<String> response = HttpClient
                .newBuilder()
                .proxy(ProxySelector.getDefault())
                .build()
                .send(request, HttpResponse.BodyHandlers.ofString()); 

                System.out.println("sent heartbeat: " + response.statusCode() + " " + json);

                //System.out.println("response: " + response.body());
                if (response.statusCode() != 200) {
                    addToErrorLog("ERROR sending heartbeat HTTP code: " + response.statusCode(), null);
                }  
            } catch (Exception e) {
                addToErrorLog("ERROR sending heartbeat data", e);
            }

            //-------------------------------------
            // if timer has elapsed, upload PCAP file to Google cloud bucket
            //-------------------------------------
            try {
                uploadCaptures();
                /*
                if (lastCapture != null) {
                    System.out.println("lastCapture: " + lastCapture);
                    System.out.println("nextSend: " + nextSend);
                    boolean send = (LocalDateTime.now().isAfter(nextSend));
                    System.out.println("send?: " + send);
                    if (send) {
                        uploadPcap();
                        lastCapture = null;
                    }
                }
                */
            } catch (Exception e) {
                addToErrorLog("ERROR Executing uploading captures", e);
            }
        }
    }





/**************************************************************
 * NETWORK DISCOVERY
 *************************************************************/
    //discover various network params 
    //mainly used to filter out normal traffic
    static void getIp() {
        //method below works on linux not mac
        try(final DatagramSocket socket = new DatagramSocket()){
            socket.connect(InetAddress.getByName("8.8.8.8"), 10002);
            deviceIp = socket.getLocalAddress().getHostAddress();
        } catch (Exception e) {
            addToErrorLog("ERROR getting device IP", e);
        }
    }
    static void getMac(String ip) {
        try {
            InetAddress localIP = InetAddress.getByName(ip);
            NetworkInterface ni = NetworkInterface.getByInetAddress(localIP);
            byte[] macAddress = ni.getHardwareAddress();
            String[] hexadecimal = new String[macAddress.length];
            for (int i = 0; i < macAddress.length; i++) {
                hexadecimal[i] = String.format("%02X", macAddress[i]);
            }
            deviceMac = String.join("-", hexadecimal);
        } catch (Exception e) {
            addToErrorLog("ERROR getting device MAC", e);
        }
    }
    static void getNetstat() {
        String netstatCmd = "netstat -rn";
        ProcessBuilder processBuilder = null;
        processBuilder = new ProcessBuilder("/bin/bash", "-c", netstatCmd);
        try {
            Process process = processBuilder.start();
            BufferedReader stdInput = new BufferedReader(new InputStreamReader(process.getInputStream()));
            BufferedReader stdError = new BufferedReader(new InputStreamReader(process.getErrorStream()));
            String s = null;
            int netstatOutputLineNumber = 0;
            int subnetChar = 0;
            int gatewayChar = 0;
            int netmaskChar = 0;
            int ifaceChar = 0;
            while ((s = stdInput.readLine()) != null) {
                if (netstatOutputLineNumber == 2) {
                    subnet = s.substring(subnetChar, subnetChar + 15).trim(); 
                    netmask = s.substring(netmaskChar, netmaskChar + 15).trim(); 
                    org.apache.commons.net.util.SubnetUtils su = new SubnetUtils(subnet, netmask);
                    subnetCIDR = su.getInfo().getCidrSignature();
                }
                if (netstatOutputLineNumber == 1) {
                    gatewayIp = s.substring(gatewayChar, gatewayChar + 15).trim(); 
                    iface = s.substring(ifaceChar, s.length()).trim(); 
                    netstatOutputLineNumber = 2;
                }
                if (s.contains("Gateway")) { 
                    subnetChar = 0;
                    gatewayChar = 16; 
                    netmaskChar = 32;
                    ifaceChar = 72;
                    netstatOutputLineNumber = 1;
                };
            } 
            while ((s = stdError.readLine()) != null) {
                addToErrorLog("ERROR in netstat output: " + s, null);
            }
            //System.out.println("netw: " + subnet + " " + netmask + " " + gatewayIP + " " + iface + " " + subnetCIDR);
        } catch (Exception e) {
            addToErrorLog("ERROR executing netstat command", e);
        }
    }
    static void getDNSserver() {
        String dnsCmd = "cat /etc/resolv.conf";
        ProcessBuilder processBuilder = null;
        processBuilder = new ProcessBuilder("/bin/bash", "-c", dnsCmd);
        try {
            Process process = processBuilder.start();
            BufferedReader stdInput = new BufferedReader(new InputStreamReader(process.getInputStream()));
            BufferedReader stdError = new BufferedReader(new InputStreamReader(process.getErrorStream()));
            String s = null;
            while ((s = stdInput.readLine()) != null) {
                if (s.contains("nameserver")) { 
                    dnsServerIp = s.substring(11, s.length()).trim();
                };  
            } 
            while ((s = stdError.readLine()) != null) {
                addToErrorLog("ERROR in resolv.conf output: " + s, null);
            }
            //System.out.println("DNS server: " + dnsServerIp);
        } catch (Exception e) {
            addToErrorLog("Error getting DNS server", e);
        }
    }
    static void getGatewayMac() {
        String arpCmd = "arp " + gatewayIp;
        ProcessBuilder processBuilder = null;
        processBuilder = new ProcessBuilder("/bin/bash", "-c", arpCmd);
        try {
            Process process = processBuilder.start();
            BufferedReader stdInput = new BufferedReader(new InputStreamReader(process.getInputStream()));
            BufferedReader stdError = new BufferedReader(new InputStreamReader(process.getErrorStream()));
            String s = null;
            while ((s = stdInput.readLine()) != null) {
                if (s.contains(gatewayIp)) { 
                    gatewayMac = s.substring(32, 50).trim();
                };
            } 
            while ((s = stdError.readLine()) != null) {
                addToErrorLog("ERROR in arp output: " + s, null);
            }
            //System.out.println("gateway MAC: " + gatewayMac);
        } catch (Exception e) {
            addToErrorLog("Error Executing get gateway MAC command", e);
        }
    }
    static void getDhcpServerIp() {
        String dhcpCmd = "echo '' | sudo -S dhclient -v";
        ProcessBuilder processBuilder = null;
        processBuilder = new ProcessBuilder("/bin/bash", "-c", dhcpCmd);
        try {
            Process process = processBuilder.start();
            BufferedReader stdError = new BufferedReader(new InputStreamReader(process.getErrorStream()));
            //not sure why this is coming in on the error stream
            String s = null;
            while ((s = stdError.readLine()) != null) {
                if (s.contains("from")) { 
                    int start = s.indexOf("from");
                    dhcpServerIp = s.substring(start + 5, start + 20).trim();
                };
            } 
            //System.out.println("DHCP IP: " + dhcpServerIp);
        } catch (Exception e) {
            addToErrorLog("Error getting DHCP IP address", e);
        }
    }
 
}