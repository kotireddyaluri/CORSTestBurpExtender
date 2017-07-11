package burp;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URL;
import java.util.List;
import javax.swing.SwingUtilities;
import java.util.ArrayList;


public class BurpExtender implements IBurpExtender, IScannerCheck
{
	private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private OutputStream output;
    private String request;
    
    List<String> payloads=new ArrayList<String>();
    IHttpRequestResponse checkRequestResponse;
    
        
    
	@Override
	public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) 
	{
		// keep a reference to our callbacks object
        this.callbacks = callbacks;
        		
		// keep a reference to our callbacks object
		this.callbacks = callbacks;

		// obtain an extension helpers object
		helpers = callbacks.getHelpers();

		// set our extension name
		callbacks.setExtensionName("CORS Test");

		// register ourselves as a custom scanner check
		callbacks.registerScannerCheck(this);
		
		
		//get the output stream for info messages
		output = callbacks.getStdout();
		
		/* 
		 * Building UI tab for user inputs
		 */
		SwingUtilities.invokeLater(new Runnable(){

			@Override
			public void run() {
				// TODO Auto-generated method stub
				
			}
			
		});
		println("Successfully Loaded CORS Test Extender");
	}//end of UI logic
	
		
	@Override
	public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) 
	{
		IHttpService httpService=baseRequestResponse.getHttpService();
		IRequestInfo rinfo=helpers.analyzeRequest(baseRequestResponse);
		List<String> headers=rinfo.getHeaders();
		payloads.clear();
		
		payloads.add("null");
		payloads.add("https://koti2.in");
		
		String host="";
		
		for(int i=0;i< headers.size();i++)
	   	{
			if(headers.get(i).startsWith("Host"))
			{
				String hosts[]=headers.get(i).split(":");
				host=hosts[1].trim();
				
				break;
			}
		}
		//payloads.add("https://"+host);
		String shost[]=host.split("\\.");
		payloads.add("https://not"+shost[shost.length-2]+"."+shost[shost.length-1]);
		
		
		request=new String(baseRequestResponse.getRequest());
		String reqBody=request.substring(rinfo.getBodyOffset());
		

		for(int p=0;p<payloads.size();p++)
		{
			//Add or update Origin header
			int orignPresent=0;
			for(int i=0;i< headers.size();i++)
		   	{
				if(headers.get(i).startsWith("Origin"))
				{
					headers.set(i, "Origin: "+payloads.get(p));
					orignPresent=1;
				}
			}
			if(orignPresent==0)
			{
				headers.add(headers.size()-1, "Origin: "+payloads.get(p));
			}
			
			//Request with updated Headers
			byte[] completeReq=helpers.buildHttpMessage(headers, reqBody.getBytes());		
			
			
			IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(
	                baseRequestResponse.getHttpService(), callbacks.makeHttpRequest(httpService, completeReq).getRequest());
			
			IResponseInfo respInfo=helpers.analyzeResponse(checkRequestResponse.getResponse());
			List<String> respHeaders=respInfo.getHeaders();
			
			
			List<int[]> matches=new ArrayList<int[]>();	
			int start=0;
			
			
			for(int i=0;i<respHeaders.size();i++)
			{
				if(respHeaders.get(i).toLowerCase().startsWith("access-control-allow-origin"))
				{
					String head[]=respHeaders.get(i).split(" ");
					String originValue=head[1];
					
					byte[] match=respHeaders.get(i).toString().getBytes();
					if(originValue.equalsIgnoreCase(payloads.get(p)))
					{
					
						while (start < checkRequestResponse.getResponse().length)
					    {
					        start = helpers.indexOf(checkRequestResponse.getResponse(), match, true, start, checkRequestResponse.getResponse().length);
					        if (start == -1)
					        {
					            break;
					        }
						    else
					        {
					        	matches.add(new int[] { start, start + match.length });
					        	start += match.length;
					        }
					    }
						
						//report the issue
						List<IScanIssue>issues = new ArrayList<>(1);
					    issues.add(new CustomScanIssue(
					    checkRequestResponse.getHttpService(),
					    helpers.analyzeRequest(checkRequestResponse).getUrl(), 
					    new IHttpRequestResponse[] { callbacks.applyMarkers(checkRequestResponse, null, matches) }, 					    
					    "CORS (Mis)configuration",
						"CORS (Mis)configuration Detected",
						"High"));
						return issues;
					}
			 }
		  }
		}
		return null;
				
	}
	
	@Override
	public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) 
	{
		return null;
	}
	
	@Override
	public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) 
	{
		if(existingIssue.getHttpMessages().equals(newIssue.getHttpMessages()))
			return -1;
		else
			return 0;
	}
	
	private void println(String toPrint) 
	{
		try
		{
		    output.write(toPrint.getBytes());
		    output.write("\n".getBytes());
		    output.flush();
		} 
		catch (IOException ioe) 
		{
		    ioe.printStackTrace();
		} 
	 }
	
}

//class implementing IScanIssue to hold our custom scan issue details
class CustomScanIssue implements IScanIssue
{
	 private IHttpService httpService;
	 private URL url;
	 private IHttpRequestResponse[] httpMessages;
	 private String name;
	 private String detail;
	 private String severity;
	
	 public CustomScanIssue(IHttpService httpService,URL url,IHttpRequestResponse[] httpMessages,String name,String detail,String severity)
	 {
	     this.httpService = httpService;
	     this.url = url;
	     this.httpMessages = httpMessages;
	     this.name = name;
	     this.detail = detail;
	     this.severity = severity;
	 }
	 
	 @Override
	 public URL getUrl()
	 {
	     return url;
	 }
	
	 @Override
	 public String getIssueName()
	 {
	     return name;
	 }
	
	 @Override
	 public int getIssueType()
	 {
	     return 0;
	 }
	
	 @Override
	 public String getSeverity()
	 {
	     return severity;
	 }
	
	 @Override
	 public String getConfidence()
	 {
	     return "Certain";
	 }
	
	 @Override
	 public String getIssueBackground()
	 {
	     return null;
	 }
	
	 @Override
	 public String getRemediationBackground()
	 {
	     return null;
	 }
	
	 @Override
	 public String getIssueDetail()
	 {
	     return detail;
	 }
	
	 @Override
	 public String getRemediationDetail()
	 {
	     return null;
	 }
	
	 @Override
	 public IHttpRequestResponse[] getHttpMessages()
	 {
	     return httpMessages;
	 }
	
	 @Override
	 public IHttpService getHttpService()
	 {
	     return httpService;
	 }
  
}