package org.wso2.micro.gateway.core.jmxagent;

import net.bytebuddy.agent.ByteBuddyAgent;
import org.wso2.micro.gateway.core.utils.ErrorUtils;

import java.io.File;
import java.lang.management.ManagementFactory;

/**
 * 
 */
public class JmxAgent {
    /**
     * 
     */
    public static void javaAgent() {
        String gwhome = System.getenv("GWHOME");
        String jmxJarFilePath = gwhome + "/lib/gateway/jmx_prometheus_javaagent-0.12.0.jar";
        String jmxArgument = "8080:" + gwhome + "/conf/Prometheus/jmxconfig.yml";
        try {
            String nameOfRunningVM = ManagementFactory.getRuntimeMXBean().getName();
            String pid = nameOfRunningVM.substring(0, nameOfRunningVM.indexOf('@'));
            ByteBuddyAgent.attach(new File(jmxJarFilePath), pid, jmxArgument);
        } catch (Exception e) {
            throw ErrorUtils.getBallerinaError(jmxJarFilePath + " & " + jmxArgument, e);
        }
    }
}
