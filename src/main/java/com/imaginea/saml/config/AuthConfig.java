package com.imaginea.saml.config;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Timer;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.MultiThreadedHttpConnectionManager;
import org.apache.velocity.app.VelocityEngine;
import org.opensaml.saml2.metadata.provider.HTTPMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.util.resource.ResourceException;
import org.opensaml.xml.parse.StaticBasicParserPool;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml.SAMLAuthenticationProvider;
import org.springframework.security.saml.SAMLBootstrap;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.SAMLLogoutFilter;
import org.springframework.security.saml.SAMLLogoutProcessingFilter;
import org.springframework.security.saml.SAMLProcessingFilter;
import org.springframework.security.saml.context.SAMLContextProviderImpl;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.log.SAMLDefaultLogger;
import org.springframework.security.saml.metadata.CachingMetadataManager;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;
import org.springframework.security.saml.metadata.MetadataDisplayFilter;
import org.springframework.security.saml.metadata.MetadataGenerator;
import org.springframework.security.saml.metadata.MetadataGeneratorFilter;
import org.springframework.security.saml.parser.ParserPoolHolder;
import org.springframework.security.saml.processor.HTTPPostBinding;
import org.springframework.security.saml.processor.HTTPRedirectDeflateBinding;
import org.springframework.security.saml.processor.SAMLBinding;
import org.springframework.security.saml.processor.SAMLProcessorImpl;
import org.springframework.security.saml.util.VelocityFactory;
import org.springframework.security.saml.websso.SingleLogoutProfile;
import org.springframework.security.saml.websso.SingleLogoutProfileImpl;
import org.springframework.security.saml.websso.WebSSOProfile;
import org.springframework.security.saml.websso.WebSSOProfileConsumer;
import org.springframework.security.saml.websso.WebSSOProfileConsumerHoKImpl;
import org.springframework.security.saml.websso.WebSSOProfileConsumerImpl;
import org.springframework.security.saml.websso.WebSSOProfileImpl;
import org.springframework.security.saml.websso.WebSSOProfileOptions;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import lombok.Getter;
import lombok.Setter;
import lombok.extern.java.Log;

/**
 * @author lakshmiabinaya
 */

/**
 * Step.1 Let’s create the main security configuration class, AuthConfig which
 * will be responsible for all SAML bean declarations and configuration.
 * 
 * @author fabianoyoschitaki
 */
@Log
@Configuration
@EnableWebSecurity
public class AuthConfig extends WebSecurityConfigurerAdapter {

	@Value("${idp.entityId}")
	@Getter
	@Setter
	private String entityId;

	@Value("${idp.appId}")
	@Getter
	@Setter
	private String appId;

	@Value("${idp.postLogoutURL}")
	@Getter
	@Setter
	private String postLogoutURL;

	@Value("${idp.metadataURL}")
	@Getter
	@Setter
	private String metadataURL;

	@Value("${server.ssl.key-store}")
	@Getter
	@Setter
	private Resource keyStore;

	@Value("${server.ssl.key-store-password}")
	@Getter
	@Setter
	private String secret;

	@Value("${server.ssl.key-alias}")
	@Getter
	@Setter
	private String alias;

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		log.info("start [configure] AuthenticationManagerBuilder");
		auth.authenticationProvider(samlAuthenticationProvider());
		log.info("end [configure] AuthenticationManagerBuilder");
	}

	@Bean
	public SAMLEntryPoint samlEntryPoint() {
		log.info("start [samlEntryPoint]");
		SAMLEntryPoint samlEntryPoint = new SAMLEntryPoint();
		samlEntryPoint.setDefaultProfileOptions(defaultWebSSOProfileOptions());
		log.info("end [samlEntryPoint]");
		return samlEntryPoint;
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		log.info("start [configure] HttpSecurity");
		/**
		 * Step.4 Let’s start configuring HttpSecurity to declare which AuthenticationEntryPoint to call 
		 * when an authentication exception is triggered:
		 */
		http
			.exceptionHandling()
			.authenticationEntryPoint(samlEntryPoint());
		
		/**
		 * Step.10.1 Disable csrf : IDP and SP belong to different domains, and since IdP will redirect to our SP, 
		 * we should disable csrf protection as the IdP has no way to know which csrf token it should provide.
		 */
		http
			.csrf()
			.disable();
		
		/**
		 * Step.10.2 Add the saml filter chain that has been built so far.
		 */
		/** 
		 * Step.11.2 Let us now add the metadata generator filter to the HttpSecurity: 
		 */
		http
			.addFilterBefore(metadataGeneratorFilter(), ChannelProcessingFilter.class)
			.addFilterAfter(samlFilter(),BasicAuthenticationFilter.class);

		/**
		 * Step.10.3 Permit certain URL patterns (/error, /saml/**). 
		 * These patterns will not need authentication and will allow the users to access the resources without a need to login.
		 */
		http.authorizeRequests()
			.antMatchers("/error").permitAll()
			.antMatchers("/saml/**").permitAll()
			.anyRequest()
			.authenticated();

		http.logout().logoutSuccessUrl("/");
		log.info("end [configure] HttpSecurity");
	}

	/**
	 * Step.2 Let’s build the spring SAML security step by step from this point. Users will
	 * try to access a SAML protected resource and fail. This failure will be
	 * handled by Spring security ExceptionTranslationFilter implementation which
	 * then will hand over to saml authentication entry point thus starting the saml
	 * authentication from your app (Service Provider or SP) to the identity
	 * provider (IdP). Add the following beans to configure entry point:
	 */
	@Bean
	public WebSSOProfileOptions defaultWebSSOProfileOptions() {
		log.info("start [defaultWebSSOProfileOptions]");
		/**
		 * Step.3 The WebSSOProfileOptions bean allows us to setup parameters of the AuthNRequest. 
		 * The AuthNRequest is the request sent from SP to IdP for asking user authentication. 
		 * We can also force authentication from IdP each time the SP sends a new AuthNRequest:
		 * 
		 * webSSOProfileOptions.setForceAuthN(true);
		 */
		WebSSOProfileOptions webSSOProfileOptions = new WebSSOProfileOptions();
		webSSOProfileOptions.setIncludeScoping(false);
		log.info("end [defaultWebSSOProfileOptions]");
		return webSSOProfileOptions;
	}

	/**
	 * Step.6 Displaying SP metadata
	 * Spring security SAML will generate SP metadata according to our SAML configuration.
	 * MetadataDisplayFilter will allow users to download the SP metadata from a specific url.
	 * This metadata will be provided/uploaded to the IDP.
	 * @return
	 */
	@Bean
	public MetadataDisplayFilter metadataDisplayFilter() {
		log.info("called [metadataDisplayFilter]");
		return new MetadataDisplayFilter();
	}

	/**
	 * Step.8 Processing SAML Response
	 */
	@Bean
	public SimpleUrlAuthenticationFailureHandler authenticationFailureHandler() {
		log.info("called [authenticationFailureHandler]");
		return new SimpleUrlAuthenticationFailureHandler();
	}

	/**
	 * Step.8 Processing SAML Response
	 */
	@Bean
	public SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler() {
		log.info("start [authenticationFailureHandler]");
		SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler = new SavedRequestAwareAuthenticationSuccessHandler();
		successRedirectHandler.setDefaultTargetUrl("/");
		log.info("end [authenticationFailureHandler]");
		return successRedirectHandler;
	}

	/**
	 * Step.8 Processing SAML Response
	 */
	@Bean
	public SAMLProcessingFilter samlWebSSOProcessingFilter() throws Exception {
		log.info("start [samlWebSSOProcessingFilter]");
		SAMLProcessingFilter samlWebSSOProcessingFilter = new SAMLProcessingFilter();
		samlWebSSOProcessingFilter.setAuthenticationManager(authenticationManager());
		samlWebSSOProcessingFilter.setAuthenticationSuccessHandler(successRedirectHandler());
		samlWebSSOProcessingFilter.setAuthenticationFailureHandler(authenticationFailureHandler());
		log.info("end [samlWebSSOProcessingFilter]");
		return samlWebSSOProcessingFilter;
	}

	/**
	 * Step.9 Logout
	 * 	Logging out can be a two step process depending on where we want the user’s session invalidated Logout
	 * 
	 * Global logout
	 * 	Global logout is a 2 step process, where we clear our SP Spring security context and 
	 * invalidate any SP cookie so that user is no more authenticated on behalf of our application 
	 * (let’s call it Spring Logout) and also terminate the sessions of all the SPs with the help of the IDP (SingleLogout)
	 * 
	 * Spring Logout only
	 * 	SingleLogout is sometimes not preferred as it terminates all the sessions from all SPs 
	 * 	(i.e multiple apps) previously authenticated by the IdP. However, if we want to only logout 
	 * 	(Spring Logout) from our app, that is also possible through configuration.
	 * 
	 * Global logout can be configured with these beans:
	 * @return
	 */
	@Bean
	public SimpleUrlLogoutSuccessHandler successLogoutHandler() {
		log.info("start [successLogoutHandler]");
		SimpleUrlLogoutSuccessHandler simpleUrlLogoutSuccessHandler = new SimpleUrlLogoutSuccessHandler();
		simpleUrlLogoutSuccessHandler.setDefaultTargetUrl(postLogoutURL);
		simpleUrlLogoutSuccessHandler.setAlwaysUseDefaultTargetUrl(true);
		log.info("end [successLogoutHandler]");
		return simpleUrlLogoutSuccessHandler;
	}

	/**
	 * Step.9 Logout
	 */
	@Bean
	public SecurityContextLogoutHandler logoutHandler() {
		log.info("start [logoutHandler]");
		SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
		logoutHandler.setInvalidateHttpSession(true);
		logoutHandler.setClearAuthentication(true);
		log.info("end [logoutHandler]");
		return logoutHandler;
	}

	/**
	 * Step.9 Logout
	 */
	@Bean
	public SAMLLogoutFilter samlLogoutFilter() {
		return new SAMLLogoutFilter(successLogoutHandler(), new LogoutHandler[] { logoutHandler() },
				new LogoutHandler[] { logoutHandler() });
	}

	/**
	 * Step.9 Logout
	 */
	@Bean
	public SAMLLogoutProcessingFilter samlLogoutProcessingFilter() {
		return new SAMLLogoutProcessingFilter(successLogoutHandler(), logoutHandler());
	}

	/**
	 * Step.11.1 SP Metadata generation
	 * 
	 * The service provider metadata can either be provided as an XML file into the application or generated. 
	 * Metadata is mandatory to allow IdP know on which SP endpoint redirect to. 
	 * We can configure MetadataGenerator bean to enable Spring SAML to generate the SP metadata
	 */
	@Bean
	public MetadataGeneratorFilter metadataGeneratorFilter() {
		return new MetadataGeneratorFilter(metadataGenerator());
	}

	/**
	 * Step.11.1 SP Metadata generation
	 * 
	 * APP_BASE_URL –This is the application’s base url after deployment, it varies according to the environment 
	 * the application is deployed in.
	 * APP_ENTITY_ID – This is the name of the application/ audience field in the application set-up for the IDP
	 * 
	 * We have disabled IdPDiscovery in ExtendedMetadata Bean as this example is targeted for single SAML IDP.  
	 * We will cover the keymanager() configuration in this section.
	 */
	@Bean
	public MetadataGenerator metadataGenerator() {
		MetadataGenerator metadataGenerator = new MetadataGenerator();
		metadataGenerator.setEntityId(getEntityId());
		metadataGenerator.setExtendedMetadata(extendedMetadata());
		metadataGenerator.setIncludeDiscoveryExtension(false);
		/** Step.11.3 KeyManager
		 * Metadata generation requires a keyManager 
		 * keyManager is responsible to encrypt the saml assertion sent to IdP.
		 * A self-signed key and keystore can be generated with the JRE keytool command:
		 * 
		 * 	keytool -genkeypair -alias mykeyalias -keypass mykeypass -storepass samlstorepass -keystore saml-keystore.jks
		 */
		metadataGenerator.setKeyManager(keyManager());
		return metadataGenerator;
	}
	
	/**
	 * Step.11.1 SP Metadata generation
	 */
	@Bean
	public ExtendedMetadata extendedMetadata() {
		ExtendedMetadata extendedMetadata = new ExtendedMetadata();
		extendedMetadata.setIdpDiscoveryEnabled(false);
		extendedMetadata.setSignMetadata(false);
		return extendedMetadata;
	}
	
	/** Step.11.3 KeyManager
	 * Metadata generation requires a keyManager 
	 * keyManager is responsible to encrypt the saml assertion sent to IdP.
	 * A self-signed key and keystore can be generated with the JRE keytool command:
	 * 
	 * 	keytool -genkeypair -alias mykeyalias -keypass mykeypass -storepass samlstorepass -keystore saml-keystore.jks
	 */
	@Bean
	public KeyManager keyManager() {
		String storePass = getSecret();
		Map<String, String> passwords = new HashMap<>();
		passwords.put(alias, getSecret());
		return new JKSKeyManager(keyStore, storePass, passwords, alias);
	}

	
	
	/**
	 * Step.5 Let’s add another bean and start initializing the Saml security filter chain i.e 
	 * the set of all SAML filters which can be involved in SAML operations.
	 */
	@Bean
	public FilterChainProxy samlFilter() throws Exception {
		List<SecurityFilterChain> chains = new ArrayList<>();

		/**
		 * Step.6.1 The filter is bound to the /saml/metadata url pattern and can be disabled for production environment if we do not want to expose it.
		 */
		chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/metadata/**"),metadataDisplayFilter()));
		
		/**
		 * Step.7 Login
		 * To directly trigger samlEntryPoint, let us add specific login url (/saml/login)  
		 * to the filter chain that will act as the entry point for SAML requests.
		 * 
		 * After user logs in, the IDP redirects the SAML response to a configured URL (e.g. «/saml/SSO») 
		 * called the SAML processing endpoint (often called Assertion Consumer URL) in the SP.  
		 * This redirection triggers the following filter bean class: SamlWebSSOProcessingFilter. 
		 * This filter processes arriving SAML messages by delegating to the WebSSOProfile. 
		 * After the SAMLAuthenticationToken is obtained, authentication providers are asked to authenticate it. 
		 * Let us configure the filter and add it to the filter chain to handle the authentication response.
		 */
		chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/login/**"), samlEntryPoint()));

		/**
		 * Step.8.1 and plug the filter into the «/saml/SSO» url.
		 */
		chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SSO/**"), samlWebSSOProcessingFilter()));

		/**
		 * Step.9.1 Logout
		 * Now, let us map the logout url (/saml/logout/**) to proper filter and add it to the filter chain.
		 * 
		 * SAMLLogoutProcessingFilter: Filter processes arriving SAML Single Logout messages by delegating to the LogoutProfile.
		 * 
		 * SAMLLogoutFilter : Upon invocation of the filter URL it is determined whether global (termination of all participating 
		 * sessions) or local (/saml/logout?local=true) (termination of only session running within Spring Security) 
		 * logout is requested based on request attribute. In case global logout is in question a LogoutRequest is sent to the IDP.
		 */
		chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/logout/**"), samlLogoutFilter()));
		chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SingleLogout/**"), samlLogoutProcessingFilter()));

		return new FilterChainProxy(chains);
	}

	/**
	 * Step.13 XML parsing
	 * 	SAML being XML based protocol, XML parser pools should be initialized to read metadata and assertions that are in XML format.
	 */
	@Bean
	public VelocityEngine velocityEngine() {
		return VelocityFactory.getEngine();
	}

	/**
	 * Step.13 XML parsing
	 * 	SAML being XML based protocol, XML parser pools should be initialized to read metadata and assertions that are in XML format.
	 */
	@Bean(initMethod = "initialize")
	public StaticBasicParserPool parserPool() {
		return new StaticBasicParserPool();
	}

	/**
	 * Step.13 XML parsing
	 * 	SAML being XML based protocol, XML parser pools should be initialized to read metadata and assertions that are in XML format.
	 */
	@Bean(name = "parserPoolHolder")
	public ParserPoolHolder parserPoolHolder() {
		return new ParserPoolHolder();
	}

	/**
	 * Step.14 SAML Binding configuration
	 * 	SAML Binding that we use depends on the IDP specifications. We use POST and 
	 * 	Redirect bindings with respect to our configuration in Onelogin and initialize SAMLProcessorImpl accordingly.
	 */
	@Bean
	public HTTPPostBinding httpPostBinding() {
		return new HTTPPostBinding(parserPool(), velocityEngine());
	}

	/**
	 * Step.14 SAML Binding configuration
	 * 	SAML Binding that we use depends on the IDP specifications. We use POST and 
	 * 	Redirect bindings with respect to our configuration in Onelogin and initialize SAMLProcessorImpl accordingly.
	 */
	@Bean
	public HTTPRedirectDeflateBinding httpRedirectDeflateBinding() {
		return new HTTPRedirectDeflateBinding(parserPool());
	}

	/**
	 * Step.14 SAML Binding configuration
	 * 	SAML Binding that we use depends on the IDP specifications. We use POST and 
	 * 	Redirect bindings with respect to our configuration in Onelogin and initialize SAMLProcessorImpl accordingly.
	 */
	@Bean
	public SAMLProcessorImpl processor() {
		Collection<SAMLBinding> bindings = new ArrayList<>();
		bindings.add(httpRedirectDeflateBinding());
		bindings.add(httpPostBinding());
		return new SAMLProcessorImpl(bindings);
	}

	/**
	 * Step.15 Other configurations
	 * 	We initialize HTTPClient with multithreaded connection manager, 
	 * 	initialize saml logger and more importantly SAML BootStrap which is responsible for the initialization of SAML library 
	 * 	and is automatically called as part of Spring initialization.
	 */
	@Bean
	public HttpClient httpClient() throws IOException {
		return new HttpClient(multiThreadedHttpConnectionManager());
	}

	/**
	 * Step.15 Other configurations
	 * 	We initialize HTTPClient with multithreaded connection manager, 
	 * 	initialize saml logger and more importantly SAML BootStrap which is responsible for the initialization of SAML library 
	 * 	and is automatically called as part of Spring initialization.
	 */
	@Bean
	public MultiThreadedHttpConnectionManager multiThreadedHttpConnectionManager() {
		return new MultiThreadedHttpConnectionManager();
	}

	/**
	 * Step.15 Other configurations
	 * 	We initialize HTTPClient with multithreaded connection manager, 
	 * 	initialize saml logger and more importantly SAML BootStrap which is responsible for the initialization of SAML library 
	 * 	and is automatically called as part of Spring initialization.
	 */
	@Bean
	public static SAMLBootstrap sAMLBootstrap() {
		return new SAMLBootstrap();
	}

	/**
	 * Step.15 Other configurations
	 * 	We initialize HTTPClient with multithreaded connection manager, 
	 * 	initialize saml logger and more importantly SAML BootStrap which is responsible for the initialization of SAML library 
	 * 	and is automatically called as part of Spring initialization.
	 */
	@Bean
	public SAMLDefaultLogger samlLogger() {
		return new SAMLDefaultLogger();
	}

	/**
	 * Step.16 Context provider
	 * 	SAMLContextProviderImpl is responsible for parsing HttpRequest/Response and determining which local entity (IDP/SP) is 
	 * 	responsible for its handling.
	 * 	
	 * This configuration is for the application that is not behind a Reverse Proxy.
	 */
	@Bean
	public SAMLContextProviderImpl contextProvider() {
		return new SAMLContextProviderImpl();
	}

	/**
	 * Step.17 Web SSO profile
	 * 	We need beans for configuring WebSSO profile and logout. We use default spring saml provided implementation
	 * 	
	 * 	WebSSOProfileConsumer Class is able to process Response objects returned from the IDP after SP initialized SSO 
	 * 		or unsolicited response from IDP.
	 * 	
	 * 	WebSSOProfile Class implements WebSSO profile and offers capabilities for SP initialized SSO and process Response 
	 * 		coming from IDP or IDP initialized SSO. HTTP-POST and HTTP-Redirect bindings are supported.
	 */
	// SAML 2.0 WebSSO Assertion Consumer
	@Bean
	public WebSSOProfileConsumer webSSOprofileConsumer() {
		return new WebSSOProfileConsumerImpl();
	}

	/**
	 * Step.17 Web SSO profile
	 * 	We need beans for configuring WebSSO profile and logout. We use default spring saml provided implementation
	 * 	
	 * 	WebSSOProfileConsumer Class is able to process Response objects returned from the IDP after SP initialized SSO 
	 * 		or unsolicited response from IDP.
	 * 	
	 * 	WebSSOProfile Class implements WebSSO profile and offers capabilities for SP initialized SSO and process Response 
	 * 		coming from IDP or IDP initialized SSO. HTTP-POST and HTTP-Redirect bindings are supported.
	 */
	// SAML 2.0 Web SSO profile
	@Bean
	public WebSSOProfile webSSOprofile() {
		return new WebSSOProfileImpl();
	}
	
	/**
	 * Step.17 Web SSO profile
	 * 	We need beans for configuring WebSSO profile and logout. We use default spring saml provided implementation
	 * 	
	 * 	WebSSOProfileConsumer Class is able to process Response objects returned from the IDP after SP initialized SSO 
	 * 		or unsolicited response from IDP.
	 * 	
	 * 	WebSSOProfile Class implements WebSSO profile and offers capabilities for SP initialized SSO and process Response 
	 * 		coming from IDP or IDP initialized SSO. HTTP-POST and HTTP-Redirect bindings are supported.
	 */
	@Bean
	public SingleLogoutProfile logoutProfile() {
		return new SingleLogoutProfileImpl();
	}

	// not used but autowired...
	// SAML 2.0 Holder-of-Key WebSSO Assertion Consumer
	@Bean
	public WebSSOProfileConsumerHoKImpl hokWebSSOprofileConsumer() {
		return new WebSSOProfileConsumerHoKImpl();
	}

	// not used but autowired...
	// SAML 2.0 Holder-of-Key Web SSO profile
	@Bean
	public WebSSOProfileConsumerHoKImpl hokWebSSOProfile() {
		return new WebSSOProfileConsumerHoKImpl();
	}
	
	/**
	 * Step.18 IdP metadata
	 * 
	 * The IDP metadata provides the means of contacting it through metadata.
	 * It can either be downloaded from the IDP (Onelogin), or if we provide the resource URL from where the metadata 
	 * can be downloaded, the Spring SAML configuration does it for us.
	 */
	@Bean
	public ExtendedMetadataDelegate idpMetadata() throws MetadataProviderException, ResourceException {

		Timer backgroundTaskTimer = new Timer(true);

		HTTPMetadataProvider httpMetadataProvider = new HTTPMetadataProvider(backgroundTaskTimer, new HttpClient(),
				metadataURL.concat(getAppId()));

		httpMetadataProvider.setParserPool(parserPool());

		ExtendedMetadataDelegate extendedMetadataDelegate = new ExtendedMetadataDelegate(httpMetadataProvider,
				extendedMetadata());
		extendedMetadataDelegate.setMetadataTrustCheck(true);
		extendedMetadataDelegate.setMetadataRequireSignature(false);
		return extendedMetadataDelegate;
	}

	/**
	 * Step.18 IdP metadata
	 * 
	 * The IDP metadata provides the means of contacting it through metadata.
	 * It can either be downloaded from the IDP (Onelogin), or if we provide the resource URL from where the metadata 
	 * can be downloaded, the Spring SAML configuration does it for us.
	 */
	@Bean
	@Qualifier("metadata")
	public CachingMetadataManager metadata() throws MetadataProviderException, ResourceException {
		List<MetadataProvider> providers = new ArrayList<>();
		providers.add(idpMetadata());
		return new CachingMetadataManager(providers);
	}

	/**
	 * Step.19 Spring security
	 * 
	 * Now let’s add some classic Spring Security configuration: – AuthenticationProvider. 
	 * The authentication provider is capable of verifying the validity of a SAMLAuthenticationToken and in case 
	 * the token is valid to create an authenticated UsernamePasswordAuthenticationToken.
	 */
	@Bean
	public SAMLAuthenticationProvider samlAuthenticationProvider() {
		SAMLAuthenticationProvider samlAuthenticationProvider = new SAMLAuthenticationProvider();
		samlAuthenticationProvider.setForcePrincipalAsString(false);
		return samlAuthenticationProvider;
	}
	
	/**
	 * Step.20 Conclusion
	 * We have completed SAML configuration in Java and the web urls in the application now are authenticated through SAML.
	 * You can find sample project here https://github.com/lakshmiabinaya/saml-java
	 * In the next section of the blog, we will address two problems:
	 * 
	 * 		How to combine SAML with other authentication mechanisms
	 * 		How to authenticate the REST APIs in the application ie what if your application uses SAML 
	 * 			for web pages and also another authentication mechanism for its REST APIs
	 */

}
