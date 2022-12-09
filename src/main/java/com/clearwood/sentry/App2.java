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

 
public class App2 {

	static Heartbeat heartbeat = new Heartbeat();
    static long pcapUploadDelay = 30L; // Delay between capture and upload in sec
    static long heartbeatInterval = 10L; // Server heartbeat interval in sec
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
    static LocalDateTime lastCapture = null; // Create a date object

/**************************************************************
 * MAIN
 *************************************************************/

	public static void main(String[] args) {
        getNetstat();
        deviceIp = getIp();
        deviceMac = getMac(deviceIp);
        getDNSserver();
        getGatewayMac();
        getDhcpServerIp();

        System.out.println("running...ok then");

		//start heartbeat
		ScheduledExecutorService es = Executors.newSingleThreadScheduledExecutor();
		es.scheduleAtFixedRate(heartbeat, 0, 1, TimeUnit.MINUTES);

        //start TCPdump
		tcpDump();
	}

/**************************************************************
 * PCAP CAPTURE AND UPLOAD
 *************************************************************/

	private static void tcpDump() {
        String captureFilter =  " src net " + subnetCIDR + " and dst host " + deviceIp + " and host not " + gatewayIp + " and host not " + dhcpServerIp;
        if (!gatewayIp.contains(dnsServerIp)) {
            captureFilter += " and host not " + dnsServerIp;
        }

        //String tcpDumpCmd = "echo '' | sudo -S tcpdump -l -i " + iface + " 'src net " + subnetCIDR + " and not " + gatewayIP + " and dst host " + deviceIp + "' -nn --immediate-mode";
        String tcpDumpCmd = "echo '' | sudo -S tcpdump -l -i " + iface + captureFilter + " -nn -U --print -C 1 -W 10 -w ~/Code/sentry/captures/cap.pcap";

        System.out.println(tcpDumpCmd);
        ProcessBuilder processBuilder = null;
        processBuilder = new ProcessBuilder("/bin/bash", "-c", tcpDumpCmd);
        try {
            Process process = processBuilder.start();
            BufferedReader stdInput = new BufferedReader(new InputStreamReader(process.getInputStream()));
            //BufferedReader stdError = new BufferedReader(new InputStreamReader(process.getErrorStream()));
    
            String s = null;
            while (true) {
                if ((s = stdInput.readLine()) != null) {
                    //publish capture to google function
                    //App2.postQueue.add("tcp:" + s);

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
            System.out.println("Error Executing tcpdump command" + e);
        }
	}

    //upload triggered by heartbeat thread
    public static void uploadPcap() throws IOException {
        try {
            deviceIp = getIp(); //IP may have changed
            String fileName = "/home/ewart/Code/sentry/captures/cap.pcap0";
    
            HttpRequest request = HttpRequest.newBuilder()
            .uri(new URI("https://save-pcap-7ffm66njka-uc.a.run.app"))
            .headers("Content-Type", "application/octet-stream")
            .POST(HttpRequest.BodyPublishers.ofFile(
                Paths.get(fileName)))
            .build();
    
            HttpResponse<String> response = HttpClient
            .newBuilder()
            .proxy(ProxySelector.getDefault())
            .build()
            .send(request, HttpResponse.BodyHandlers.ofString());
    
            System.out.println("sent file code: " + response.statusCode() +  " " + fileName );
    
            //System.out.println("response: " + response.body());
            if (response.statusCode() != 200) {
                System.out.println("ERROR HTTP code: " + response.statusCode());
                //TODO
            }  
        } catch (Exception e) {
            //TODO catch
            System.out.println("ERROR sending data: " + e.getMessage());
        }
    }


    private static class Heartbeat implements Runnable {
        @Override
        public void run() {

            //-------------------------------------
            // send heartbeat
            try {
                JSONObject jo = new JSONObject();
                deviceIp = getIp(); //IP may have changed
                jo.put("heartbeat", LocalDateTime.now().toString());
                JSONObject joWrapper = new JSONObject();
                joWrapper.put(deviceMac, jo);

                String json = jo.toString();
                HttpRequest request = HttpRequest.newBuilder()
                .uri(new URI("https://us-central1-clearwood-199118.cloudfunctions.net/report-1"))
                .headers("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json))
                .build();

                HttpResponse<String> response = HttpClient
                .newBuilder()
                .proxy(ProxySelector.getDefault())
                .build()
                .send(request, HttpResponse.BodyHandlers.ofString());

                System.out.println("sent data: " + response.statusCode() + " " + json);

                //System.out.println("response: " + response.body());
                if (response.statusCode() != 200) {
                    System.out.println("ERROR HTTP code: " + response.statusCode());
                    //TODO
                }  
            } catch (Exception e) {
                //TODO catch
                System.out.println("ERROR sending data: " + e.getMessage());
            }


            //-------------------------------------
            // if timer has elapsed, upload PCAP file to Google cloud bucket
            try {
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
            } catch (Exception e) {
                System.out.println("Error Executing tcpdump command" + e);
            }
        }
    }





/**************************************************************
 * NETWORK DISCOVERY
 *************************************************************/

    static String getIp() {
        //method below works on linux not mac
        String ip = "not found";
        try(final DatagramSocket socket = new DatagramSocket()){
            socket.connect(InetAddress.getByName("8.8.8.8"), 10002);
            ip = socket.getLocalAddress().getHostAddress();
        } catch (Exception e) {
            //TODO
        }
        return ip;
    }

    static String getMac(String ip) {
        String mac = "not found";
        try {
            InetAddress localIP = InetAddress.getByName(ip);
            NetworkInterface ni = NetworkInterface.getByInetAddress(localIP);
            byte[] macAddress = ni.getHardwareAddress();

            String[] hexadecimal = new String[macAddress.length];
            for (int i = 0; i < macAddress.length; i++) {
                hexadecimal[i] = String.format("%02X", macAddress[i]);
            }
            mac = String.join("-", hexadecimal);
        } catch (Exception e) {
            //TODO
        }
        return mac;
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
                System.out.println("error: " + s);
            }
            //System.out.println("netw: " + subnet + " " + netmask + " " + gatewayIP + " " + iface + " " + subnetCIDR);
        } catch (Exception e) {
            System.out.println("Error Executing netstat command" + e.getStackTrace());
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
                System.out.println("error: " + s);
            }
            System.out.println("DNS server: " + dnsServerIp);
        } catch (Exception e) {
            System.out.println("Error Executing get DNS server command" + e.getStackTrace());
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
                System.out.println("error: " + s);
            }
            System.out.println("gateway MAC: " + gatewayMac);
        } catch (Exception e) {
            System.out.println("Error Executing get gateway MAC command" + e.getStackTrace());
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
            System.out.println("DHCP IP: " + dhcpServerIp);
        } catch (Exception e) {
            System.out.println("Error Executing get DHCP IP command" + e.getStackTrace());
        }
    }


}