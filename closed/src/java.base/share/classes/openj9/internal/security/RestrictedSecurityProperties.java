/*
 * ===========================================================================
 * (c) Copyright IBM Corp. 2022, 2023 All Rights Reserved
 * ===========================================================================
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * IBM designates this particular file as subject to the "Classpath" exception
 * as provided by IBM in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, see <http://www.gnu.org/licenses/>.
 *
 * ===========================================================================
 */

package openj9.internal.security;

import java.security.Provider.Service;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;

import sun.security.util.Debug;

public final class RestrictedSecurityProperties {

    private static final Debug debug = Debug.getInstance("semerufips");

    private static RestrictedSecurityProperties instance;

    private String descName;
    private String descNumber;
    private String descPolicy;
    private String descSunsetDate;

    // Security properties.
    private String jdkTlsDisabledNamedCurves;
    private String jdkTlsDisabledAlgorithms;
    private String jdkTlsDphemeralDHKeySize;
    private String jdkTlsLegacyAlgorithms;
    private String jdkCertpathDisabledAlgorithms;
    private String jdkSecurityLegacyAlgorithm;
    private String keyStoreType;
    private String keyStore;

    // For Secure Random.
    private String jdkSecureRandomProvider;
    private String jdkSecureRandomAlgorithm;

    // Provider with argument (provider name + optional argument).
    private List<String> providers;
    // Provider without argument.
    private List<String> providersSN;
    // The map is keyed by provider name.
    private Map<String, Constraint[]> providerConstraints;

    private final int userSecurityNum;
    private final boolean userSecurityTrace;
    private final boolean userSecurityAudit;
    private final boolean userSecurityHelp;

    private final String propsPrefix;

    // The java.security properties.
    private final Properties securityProps;

    /**
     *
     * @param num   the restricted security setting number
     * @param props the java.security properties
     * @param trace the user security trace
     * @param audit the user security audit
     * @param help  the user security help
     */
    private RestrictedSecurityProperties(int num, Properties props, boolean trace, boolean audit, boolean help) {

        Objects.requireNonNull(props);

        userSecurityNum = num;
        userSecurityTrace = trace;
        userSecurityAudit = audit;
        userSecurityHelp = help;
        securityProps = props;

        propsPrefix = "RestrictedSecurity" + userSecurityNum;

        providers = new ArrayList<>();
        providersSN = new ArrayList<>();
        providerConstraints = new HashMap<>();

        // Initialize the properties.
        init();
    }

    /**
     * Get instance of RestrictedSecurityProperties.
     *
     * @param num   the restricted security setting number
     * @param props the java.security properties
     * @param trace the user security trace
     * @param audit the user security audit
     * @param help  the user security help
     * @return the created RestrictedSecurityProperties instance
     */
    public static RestrictedSecurityProperties createInstance(int num, Properties props, boolean trace,
            boolean audit, boolean help) {
        if (instance != null) {
            throw new RuntimeException(
                    "Restricted security mode is already initialized. Can't be initialized twice.");
        }
        instance = new RestrictedSecurityProperties(num, props, trace, audit, help);
        return instance;
    }

    /**
     * Get instance of RestrictedSecurityProperties.
     *
     * @return the created RestrictedSecurityProperties instance
     */
    public static RestrictedSecurityProperties getInstance() {
        if (instance == null) {
            throw new RuntimeException(
                    "Restricted security mode initialization error, call createInstance() first.");
        }
        return instance;
    }

    /**
     * Initialize the restricted security properties.
     */
    private void init() {
        if (debug != null) {
            debug.println("Initializing restricted security mode.");
        }

        try {
            // Print out the Help and Audit info.
            if (userSecurityHelp || userSecurityAudit || userSecurityTrace) {
                if (userSecurityHelp) {
                    printHelp();
                }
                if (userSecurityAudit) {
                    listAudit();
                }
                if ((userSecurityNum == 0)) {
                    if (userSecurityTrace) {
                        new RuntimeException(
                                "Unable to list the trace info without specify the security policy number.")
                                .printStackTrace();
                        System.exit(1);
                    } else {
                        if (debug != null) {
                            debug.println("Print out the info and exit.");
                        }
                        System.exit(0);
                    }
                }
            }

            // Load the restricted security providers from java.security properties.
            initProviders();
            // Load the restricted security properties from java.security properties.
            initProperties();
            // Load the restricted security provider constraints from java.security properties.
            initConstraints();

            if (debug != null) {
                debug.println("Initialized restricted security mode.");
            }
        } catch (Exception e) {
            if (debug != null) {
                debug.println("Unable to initialize restricted security mode.");
            }
            e.printStackTrace();
            System.exit(1);
        }
    }

    /**
     * Load restricted security provider.
     */
    private void initProviders() {

        if (debug != null) {
            debug.println("Loading restricted security providers.");
        }

        for (int pNum = 1;; ++pNum) {
            String providerInfo = securityProps
                    .getProperty(propsPrefix + ".jce.provider." + pNum);

            if (providerInfo == null || providerInfo.trim().isEmpty()) {
                break;
            }

            if (!areBracketsBalanced(providerInfo)) {
                new RuntimeException("Provider format is incorrect: " + providerInfo).printStackTrace();
                System.exit(1);
            }

            int pos = providerInfo.indexOf('[');
            String providerName = (pos < 0) ? providerInfo.trim() : providerInfo.substring(0, pos).trim();
            // Provider with argument (provider name + optional argument).
            providers.add(pNum - 1, providerName);

            // Remove the provider's optional arguments if there are.
            pos = providerName.indexOf(' ');
            providerName = (pos < 0) ? providerName.trim() : providerName.substring(0, pos).trim();
            // Remove the provider's class package names if there are.
            pos = providerName.lastIndexOf('.');
            providerName = (pos < 0) ? providerName : providerName.substring(pos + 1, providerName.length());
            // Provider without arguments and package names.
            providersSN.add(pNum - 1, providerName);

            if (debug != null) {
                debug.println("Loaded restricted security provider: " + providers.get(pNum - 1) + " with short name: "
                        + providersSN.get(pNum - 1));
            }
        }

        if (providers.isEmpty()) {
            new RuntimeException("Restricted security mode provider list empty, "
                    + "or no such restricted security policy in java.security file.").printStackTrace();
            System.exit(1);
        }
    }

    /**
     * Load restricted security properties.
     */
    private void initProperties() {

        if (debug != null) {
            debug.println("Loading restricted security properties.");
        }

        descName = parseProperty(securityProps.getProperty(propsPrefix + ".desc.name"));
        descNumber = parseProperty(securityProps.getProperty(propsPrefix + ".desc.number"));
        descPolicy = parseProperty(securityProps.getProperty(propsPrefix + ".desc.policy"));
        descSunsetDate = parseProperty(securityProps.getProperty(propsPrefix + ".desc.sunsetDate"));

        jdkTlsDisabledNamedCurves = parseProperty(
                securityProps.getProperty(propsPrefix + ".tls.disabledNamedCurves"));
        jdkTlsDisabledAlgorithms = parseProperty(
                securityProps.getProperty(propsPrefix + ".tls.disabledAlgorithms"));
        jdkTlsDphemeralDHKeySize = parseProperty(
                securityProps.getProperty(propsPrefix + ".tls.ephemeralDHKeySize"));
        jdkTlsLegacyAlgorithms = parseProperty(
                securityProps.getProperty(propsPrefix + ".tls.legacyAlgorithms"));
        jdkCertpathDisabledAlgorithms = parseProperty(
                securityProps.getProperty(propsPrefix + ".jce.certpath.disabledAlgorithms"));
        jdkSecurityLegacyAlgorithm = parseProperty(
                securityProps.getProperty(propsPrefix + ".jce.legacyAlgorithms"));
        keyStoreType = parseProperty(
                securityProps.getProperty(propsPrefix + ".keystore.type"));
        keyStore = parseProperty(
                securityProps.getProperty(propsPrefix + ".javax.net.ssl.keyStore"));

        jdkSecureRandomProvider = parseProperty(
                securityProps.getProperty(propsPrefix + ".securerandom.provider"));
        jdkSecureRandomAlgorithm = parseProperty(
                securityProps.getProperty(propsPrefix + ".securerandom.algorithm"));

        if (debug != null) {
            debug.println("Loaded restricted security properties.");
        }
    }

    /**
     * Load security constraints with type, algorithm, attributes.
     *
     * Example:
     * RestrictedSecurity1.jce.provider.1 = SUN [{CertPathBuilder, PKIX, *}, {Policy,
     * JavaPolicy, *}, {CertPathValidator, *, *}].
     */
    private void initConstraints() {

        for (int pNum = 1; pNum <= providersSN.size(); pNum++) {

            String providerName = providersSN.get(pNum - 1);
            String providerInfo = securityProps
                    .getProperty(propsPrefix + ".jce.provider." + pNum);

            if (debug != null) {
                debug.println("Loading constraints for security provider: " + providerName);
            }

            // Check if the provider has constraints
            if (providerInfo.indexOf('[') < 0 && providerInfo.indexOf(']') < 0) {
                if (debug != null) {
                    debug.println("No constraints for security provider: " + providerName);
                }
                continue;
            }

            // Remove the whitespaces in the format separator if there are.
            providerInfo = providerInfo.trim()
                    .replaceAll("\\[\\s*\\{", "[{")
                    .replaceAll("\\}\\s*\\]", "}]")
                    .replaceAll("\\}\\s*\\,\\s*\\{", "},{");

            int startIndex = providerInfo.indexOf("[{");
            int endIndex = providerInfo.indexOf("}]");

            // Provider with constraints.
            if ((startIndex > 0) && (endIndex > 0)) {
                String[] constrArray = providerInfo
                        .substring(startIndex + 2, endIndex).split("\\},\\{");

                if (constrArray.length <= 0) {
                    new RuntimeException("Constraint format is incorrect: " + providerInfo).printStackTrace();
                    System.exit(1);
                }

                // Constraint object array.
                // For each constraint type, algorithm and attributes.
                Constraint[] constraints = new Constraint[constrArray.length];

                int cNum = 0;
                for (String constr : constrArray) {
                    String[] input = constr.split(",");

                    // Each constraint must includes 3 fields(type, algorithm, attributes).
                    if (input.length != 3) {
                        new RuntimeException("Constraint format is incorrect: " + providerInfo).printStackTrace();
                        System.exit(1);
                    }

                    String inType = input[0].trim();
                    String inAlgorithm = input[1].trim();
                    String inAttributes = input[2].trim();

                    // Each attribute must includes 2 fields(key and value) or *.
                    if (!isAsterisk(inAttributes)) {
                        String[] attributeArray = inAttributes.split(":");
                        for (String attribute : attributeArray) {
                            String[] in = attribute.split("=");
                            if (in.length != 2) {
                                new RuntimeException("Constraint attributes format is incorrect: " + providerInfo)
                                        .printStackTrace();
                                System.exit(1);
                            }
                        }
                    }

                    Constraint constraint = new Constraint(inType, inAlgorithm, inAttributes);

                    if (debug != null) {
                        debug.println("Loading constraints for provider " + providerName
                                + " with constraints type: " + constraint.type
                                + " algorithm: " + constraint.algorithm
                                + " attributes: " + constraint.attributes);
                    }
                    constraints[cNum] = constraint;
                    cNum++;
                }
                providerConstraints.put(providerName, constraints);
                if (debug != null) {
                    debug.println("Loaded constraints for security provider: " + providerName);
                }
            } else {
                new RuntimeException("Constraint format is incorrect: " + providerInfo).printStackTrace();
                System.exit(1);
            }
        }
    }

    /**
     * Check if the Service is allowed in restricted security mode.
     *
     * @param service the Service to check
     * @return true if the Service is allowed
     */
    public boolean isServiceAllowed(Service service) {

        String providerName = service.getProvider().getName();
        String type = service.getType();
        String algorithm = service.getAlgorithm();

        // Provider with argument, remove argument.
        // e.g. SunPKCS11-NSS-FIPS, remove argument -NSS-FIPS.
        int pos = providerName.indexOf('-');
        providerName = (pos < 0) ? providerName : providerName.substring(0, pos);

        Constraint[] constraints = providerConstraints.get(providerName);

        // Go into the security provider constraints check if there are.
        if (constraints != null && constraints.length > 0) {

            for (Constraint constraint : constraints) {

                String cType = constraint.type;
                String cAlgorithm = constraint.algorithm;
                String cAttribute = constraint.attributes;

                boolean cTypePut = isAsterisk(cType)
                        || type.equals(cType);
                boolean cAlgorithmPut = isAsterisk(cAlgorithm)
                        || algorithm.equals(cAlgorithm);
                boolean cAttributePut = isAsterisk(cAttribute);

                // For type and algorithm match, and attribute is *.
                if (cTypePut && cAlgorithmPut && cAttributePut) {
                    if (debug != null) {
                        debug.println("Security constraints check."
                                + " Service type: " + type
                                + " Algorithm " + algorithm
                                + " is allowed in provider " + providerName);
                    }
                    return true;
                }

                // For type and algorithm match, and attribute is not *.
                // Then continue checking attributes.
                if (cTypePut && cAlgorithmPut) {
                    String[] cAttributeArray = constraint.attributes.split(":");

                    // For each attribute, must be all matched for return allowed.
                    for (String attribute : cAttributeArray) {
                        String[] input = attribute.split("=");

                        String cName = input[0].trim();
                        String cValue = input[1].trim();
                        String sValue = service.getAttribute(cName);
                        if ((sValue == null) && !cValue.equalsIgnoreCase(sValue)) {
                            // Any of the attribute not match, return service is not allowed
                            return false;
                        }
                    }
                    if (debug != null) {
                        debug.println(
                                "Security constraints check."
                                        + " Service type: " + type
                                        + " Algorithm: " + algorithm
                                        + " Attribute: " + constraint.attributes
                                        + " is allowed in provider: " + providerName);
                    }
                    return true;
                }
            }
            if (debug != null) {
                debug.println("Security constraints check."
                        + " Service type: " + type
                        + " Algorithm: " + algorithm
                        + " is NOT allowed in provider " + providerName);
            }
            // Go through all the constraints for the provider,
            // no match, then return NOT allowed.
            return false;
        }
        // This provider no any constraint, then return allowed.
        return true;
    }

    /**
     * Check if the provider is allowed in restricted security mode.
     *
     * @param providerName the provider to check
     * @return true if the provider is allowed
     */
    public boolean isProviderAllowed(String providerName) {

        if (debug != null) {
            debug.println("Checking the provider " + providerName + " in the restricted security mode.");
        }

        // Remove the provider class package name if there is.
        int pos = providerName.lastIndexOf('.');
        providerName = (pos < 0) ? providerName : providerName.substring(pos + 1, providerName.length());

        // Remove argument, e.g. -NSS-FIPS, if there is.
        pos = providerName.indexOf('-');
        providerName = (pos < 0) ? providerName : providerName.substring(0, pos);

        // Check if the provider is in the restricted security provider list.
        // If not, the provider won't be registered.
        if (providersSN.contains(providerName)) {
            if (debug != null) {
                debug.println("The provider " + providerName + " is allowed in the restricted security mode.");
            }
            return true;
        }

        if (debug != null) {
            debug.println("The provider " + providerName + " is not allowed in the restricted security mode.");

            debug.println("Stack trace:");
            StackTraceElement[] elements = Thread.currentThread().getStackTrace();
            for (int i = 1; i < elements.length; i++) {
                StackTraceElement stack = elements[i];
                debug.println("\tat " + stack.getClassName() + "." + stack.getMethodName() + "("
                        + stack.getFileName() + ":" + stack.getLineNumber() + ")");
            }
        }
        return false;
    }

    /**
     * Check if the provider is allowed in restricted security mode.
     *
     * @param providerClazz the provider class to check
     * @return true if the provider is allowed
     */
    public boolean isProviderAllowed(Class<?> providerClazz) {

        String providerName = providerClazz.getName();

        // Check if the specified class extends java.security.Provider
        if (!java.security.Provider.class.isAssignableFrom(providerClazz)) {
            if (debug != null) {
                debug.println("The provider class " + providerName + " does not extend java.security.Provider.");
            }
            // For class doesn't extend java.security.Provider, no need to
            // check allowed or not allowed, always return true to load it.
            return true;
        }
        return isProviderAllowed(providerName);
    }

    /**
     * List audit info if userSecurityAudit is true, default as false.
     */
    protected void listAudit() {

        System.out.println();
        System.out.println("Restricted Security Audit Info:");
        System.out.println("===============================");

        for (int num = 1;; ++num) {
            String desc = securityProps.getProperty("RestrictedSecurity" + num + ".desc.name");
            if (desc == null || desc.trim().isEmpty()) {
                break;
            }
            System.out.println("RestrictedSecurity" + num + ".desc.name: "
                    + securityProps.getProperty("RestrictedSecurity" + num + ".desc.name"));
            System.out.println("RestrictedSecurity" + num + ".desc.number: "
                    + parseProperty(securityProps.getProperty("RestrictedSecurity" + num + ".desc.number")));
            System.out.println("RestrictedSecurity" + num + ".desc.policy: "
                    + parseProperty(securityProps.getProperty("RestrictedSecurity" + num + ".desc.policy")));
            System.out.println("RestrictedSecurity" + num + ".desc.sunsetDate: "
                    + parseProperty(securityProps.getProperty("RestrictedSecurity" + num + ".desc.sunsetDate")));
            System.out.println();
        }
    }

    /**
     * List trace info if userSecurityTrace is true, default as false.
     */
    protected void listTrace() {

        System.out.println();
        System.out.println("Restricted Security Trace Info:");
        System.out.println("===============================");
        System.out.println(propsPrefix + ".desc.name: " + descName);
        System.out.println(propsPrefix + ".desc.number: " + descNumber);
        System.out.println(propsPrefix + ".desc.policy: " + descPolicy);
        System.out.println(propsPrefix + ".desc.sunsetDate: " + descSunsetDate);
        System.out.println();

        // List restrictions.
        System.out.println(propsPrefix + ".tls.disabledNamedCurves: "
                + parseProperty(securityProps.getProperty("jdk.tls.disabledNamedCurves")));
        System.out.println(propsPrefix + ".tls.disabledAlgorithms: "
                + parseProperty(securityProps.getProperty("jdk.tls.disabledAlgorithms")));
        System.out.println(propsPrefix + ".tls.ephemeralDHKeySize: "
                + parseProperty(securityProps.getProperty("jdk.tls.ephemeralDHKeySize")));
        System.out.println(propsPrefix + ".tls.legacyAlgorithms: "
                + parseProperty(securityProps.getProperty("jdk.tls.legacyAlgorithms")));
        System.out.println(propsPrefix + ".jce.certpath.disabledAlgorithms: "
                + parseProperty(securityProps.getProperty("jdk.certpath.disabledAlgorithms")));
        System.out.println(propsPrefix + ".jce.legacyAlgorithms: "
                + parseProperty(securityProps.getProperty("jdk.security.legacyAlgorithm")));
        System.out.println();

        System.out.println(propsPrefix + ".keystore.type: "
                + parseProperty(securityProps.getProperty("keystore.type")));
        System.out.println(propsPrefix + ".javax.net.ssl.keyStore: "
                + keyStore);
        System.out.println(propsPrefix + ".securerandom.provider: "
                + jdkSecureRandomProvider);
        System.out.println(propsPrefix + ".securerandom.algorithm: "
                + jdkSecureRandomAlgorithm);

        // List providers.
        System.out.println();
        for (int pNum = 1; pNum <= providers.size(); pNum++) {
            System.out.println(propsPrefix + ".jce.provider." + pNum + ": "
                    + providers.get(pNum - 1));
        }

        System.out.println();
    }

    /**
     * Print help info if userSecurityHelp is ture, default as false.
     */
    protected void printHelp() {

        System.out.println();
        System.out.println("Restricted Security Mode Usage:");
        System.out.println("===============================");

        System.out.println(
                "-Dsemeru.restrictedsecurity=<n>  This flag will select the settings for the user " +
                "specified restricted security policy.");
        System.out.println(
                "-Dsemeru.restrictedsecurity=audit  This flag will list the name and number of all " +
                "configured restricted security policies.");
        System.out.println(
                "-Dsemeru.restrictedsecurity=trace  This flag will list all properties relevant to " +
                "the restricted security mode, including the existing default properties and the " +
                "restricted security properties.");
        System.out.println("-Dsemeru.restrictedsecurity=help  This flag will print help message.");

        System.out.println();
        System.out.println("e.g.");
        System.out.println("    -Dsemeru.restrictedsecurity=1,trace,audit,help");
        System.out.println("    -Dsemeru.restrictedsecurity=help");

        System.out.println();
    }

    /**
     * Check if the input string is null and empty.
     *
     * @param string the input string
     * @return true if the input string is null and emtpy
     */
    private static boolean isNullOrBlank(String string) {
        return (string == null) || string.isBlank();
    }

    /**
     * Check if the input string is null. If null return "".
     *
     * @param string the input string
     * @return "" if the string is null
     */
    private static String parseProperty(String string) {
        return (string != null) ? string.trim() : "";
    }

    /**
     * Function to check if brackets are balanced.
     *
     * @param string input string for checking
     * @return true if the brackets are balanced
     */
    private boolean areBracketsBalanced(String string) {

        Deque<Character> deque = new LinkedList<>();

        for (char ch : string.toCharArray()) {
            if (ch == '{' || ch == '[' || ch == '(') {
                deque.addFirst(ch);
            } else if (ch == '}' || ch == ']' || ch == ')') {
                if (!deque.isEmpty()
                        && ((deque.peekFirst() == '{' && ch == '}')
                                || (deque.peekFirst() == '[' && ch == ']')
                                || (deque.peekFirst() == '(' && ch == ')'))) {
                    deque.removeFirst();
                } else {
                    return false;
                }
            }
        }
        return deque.isEmpty();
    }

    /**
     * Check if the input string is asterisk (*).
     *
     * @param string input string for checking
     * @return true if the input string is asterisk
     */
    private boolean isAsterisk(String string) {
        return "*".equals(string);
    }

    /**
     * Nested class for provider's constraints
     */
    private static final class Constraint {
        final String type;
        final String algorithm;
        final String attributes;

        Constraint(String type, String algorithm, String attributes) {
            super();
            this.type = type;
            this.algorithm = algorithm;
            this.attributes = attributes;
        }
    }

    public String getDescriptionName() {
        return descName;
    }

    public String getDescriptionNumber() {
        return descNumber;
    }

    public String getDescriptionPolicy() {
        return descPolicy;
    }

    public String getDescriptionSunsetDate() {
        return descSunsetDate;
    }

    public String getJdkTlsDisabledNamedCurves() {
        return jdkTlsDisabledNamedCurves;
    }

    public String getJdkTlsDisabledAlgorithms() {
        return jdkTlsDisabledAlgorithms;
    }

    public String getJdkTlsDphemeralDHKeySize() {
        return jdkTlsDphemeralDHKeySize;
    }

    public String getJdkTlsLegacyAlgorithms() {
        return jdkTlsLegacyAlgorithms;
    }

    public String getJdkCertpathDisabledAlgorithms() {
        return jdkCertpathDisabledAlgorithms;
    }

    public String getJdkSecurityLegacyAlgorithm() {
        return jdkSecurityLegacyAlgorithm;
    }

    public String getKeyStoreType() {
        return keyStoreType;
    }

    public String getKeyStore() {
        return keyStore;
    }

    public List<String> getProviders() {
        return providers;
    }

    public String getJdkSecureRandomProvider() {
        return jdkSecureRandomProvider;
    }

    public String getJdkSecureRandomAlgorithm() {
        return jdkSecureRandomAlgorithm;
    }
}
