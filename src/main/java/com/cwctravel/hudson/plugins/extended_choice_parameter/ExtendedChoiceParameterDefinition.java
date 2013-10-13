/*
 *Copyright (c) 2013 Costco, Vimil Saju
 *Copyright (c) 2013 John DiMatteo
 *See the file license.txt for copying permission.
 */

package com.cwctravel.hudson.plugins.extended_choice_parameter;

import hudson.Extension;
import hudson.model.ParameterValue;
import hudson.model.ParameterDefinition;
import hudson.util.FormValidation;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.net.Socket;
import java.net.URL;
import java.nio.charset.Charset;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.ServletException;

import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.tools.ant.Project;
import org.apache.tools.ant.taskdefs.Property;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;

import au.com.bytecode.opencsv.CSVReader;
import ch.ethz.ssh2.ChannelCondition;
import ch.ethz.ssh2.Connection;
import ch.ethz.ssh2.Session;
import ch.ethz.ssh2.StreamGobbler;

public class ExtendedChoiceParameterDefinition extends ParameterDefinition {
	private static final long serialVersionUID = -2946187268529865645L;

	private final static Logger LOG = Logger.getLogger(ExtendedChoiceParameterDefinition.class.getName());

	public static final String PARAMETER_TYPE_SINGLE_SELECT = "PT_SINGLE_SELECT";

	public static final String PARAMETER_TYPE_MULTI_SELECT = "PT_MULTI_SELECT";

	public static final String PARAMETER_TYPE_CHECK_BOX = "PT_CHECKBOX";

	public static final String PARAMETER_TYPE_RADIO = "PT_RADIO";

	public static final String PARAMETER_TYPE_TEXT_BOX = "PT_TEXTBOX";
        
	public static final String PARAMETER_TYPE_MULTI_LEVEL_SINGLE_SELECT = "PT_MULTI_LEVEL_SINGLE_SELECT";
        
	public static final String PARAMETER_TYPE_MULTI_LEVEL_MULTI_SELECT = "PT_MULTI_LEVEL_MULTI_SELECT";

	@Extension
	public static class DescriptorImpl extends ParameterDescriptor {
		@Override
		public String getDisplayName() {
			return Messages.ExtendedChoiceParameterDefinition_DisplayName();
		}

		public FormValidation doCheckPropertyFile(@QueryParameter final String propertyFile, @QueryParameter final String propertyKey, @QueryParameter final String type) throws IOException, ServletException {
			if(StringUtils.isBlank(propertyFile)) {
				return FormValidation.ok();
			}

			Project project = new Project();
			Property property = new Property();
			property.setProject(project);

			File prop = new File(propertyFile);
			try {
				if(prop.exists()) {
					property.setFile(prop);
				}
				else {
					URL propertyFileUrl = new URL(propertyFile);
					property.setUrl(propertyFileUrl);
				}
				property.execute();
			}
			catch(Exception e) {
				return FormValidation.warning(Messages.ExtendedChoiceParameterDefinition_PropertyFileDoesntExist(), propertyFile);
			}

			if(   type.equals(PARAMETER_TYPE_MULTI_LEVEL_SINGLE_SELECT)
				 || type.equals(PARAMETER_TYPE_MULTI_LEVEL_MULTI_SELECT))
			{
				return FormValidation.ok();
			}
			else if(StringUtils.isNotBlank(propertyKey)) {
				if(project.getProperty(propertyKey) != null) {
					return FormValidation.ok();
				}
				else {
					return FormValidation.warning(Messages.ExtendedChoiceParameterDefinition_PropertyFileExistsButProvidedKeyIsInvalid(), propertyFile, propertyKey);
				}
			}
			else {
				return FormValidation.warning(Messages.ExtendedChoiceParameterDefinition_PropertyFileExistsButNoProvidedKey(), propertyFile);
			}
		}

		public FormValidation doCheckPropertyKey(@QueryParameter final String propertyFile, @QueryParameter final String propertyKey,
						@QueryParameter final String type) throws IOException, ServletException {
			return doCheckPropertyFile(propertyFile, propertyKey, type);
		}

		public FormValidation doCheckDefaultPropertyFile(@QueryParameter final String defaultPropertyFile,
				@QueryParameter final String defaultPropertyKey, @QueryParameter final String type) throws IOException, ServletException {
			return doCheckPropertyFile(defaultPropertyFile, defaultPropertyKey, type);
		}

		public FormValidation doCheckDefaultPropertyKey(@QueryParameter final String defaultPropertyFile,
						@QueryParameter final String defaultPropertyKey, @QueryParameter final String type) throws IOException, ServletException
		{
			return doCheckPropertyFile(defaultPropertyFile, defaultPropertyKey, type);
		}

		// FIXME SSH validation
		// public FormValidation doChecksshHostname(
		// @QueryParameter final String sshHostname) {
		// System.out.println("ExtendedChoiceParameterDefinition.DescriptorImpl.doCheckSsHPassword()");
		// return doInternalCheckCommand(null, sshHostname, null, null, null);
		// }
		//
		// public FormValidation doCheckSSHPublicKey(@QueryParameter final
		// String command,
		// @QueryParameter final String sshHostname, @QueryParameter final
		// String sshUsername,
		// @QueryParameter final String sshPublicKey) {
		// System.out.println("ExtendedChoiceParameterDefinition.DescriptorImpl.doCheckSsHPublicKey()");
		// return doInternalCheckCommand(command, sshHostname, sshUsername,
		// null, sshPublicKey);
		// }

		public FormValidation doCheckSshHostname(@QueryParameter final String sshHostname) {
			if (StringUtils.isBlank(sshHostname)) {
				return FormValidation.ok();
			}
			Socket socket = null;
			boolean reachable = false;
			try {
				socket = new Socket(sshHostname, 22);
				reachable = true;
			} catch (Exception e) {
				return FormValidation.error(e, e.getMessage());
			} finally {
				if (socket != null)
					try {
						socket.close();
					} catch (IOException e) {
						return FormValidation.error(e, e.getMessage());
					}
			}
			if (!reachable) {
				return FormValidation.error(String.format("Host %s not found", sshHostname));
			}
			return FormValidation.ok();
		}

		public FormValidation doCheckCommand(@QueryParameter final String command) {
			return doInternalCheckCommand(command, null, null, null, null);
		}

		private FormValidation doInternalCheckCommand(final String command, final String sshHostname,
				final String sshUsername, final String sshPassword, final String sshPublicKey) {
			if (StringUtils.isBlank(command)) {
				return FormValidation.ok();
			}
			try {
				if (StringUtils.isBlank(sshHostname)) {
					String[] envs = new String[System.getenv().size()];
					int i = 0;
					for (String key : System.getenv().keySet()) {
						envs[i] = String.format("%s=%s", key, System.getenv().get(key));
						i++;
					}
					Process process = Runtime.getRuntime().exec(command, envs);
					if (process.waitFor() != 0) {
						StringWriter writer = new StringWriter();
						try {
							IOUtils.copy(process.getErrorStream(), writer, Charset.defaultCharset().name());
							return FormValidation.error(writer.toString());
						} finally {
							writer.close();
						}
					}
				} else {
					Connection connection = new Connection(sshHostname);
					connection.connect();

					boolean isAuthenticated;
					if (!StringUtils.isBlank(sshPublicKey)) {
						isAuthenticated = connection.authenticateWithPublicKey(sshUsername, sshPublicKey.toCharArray(),
								null);
					} else {
						isAuthenticated = connection.authenticateWithPassword(sshUsername, sshPassword);
					}

					if (!isAuthenticated) {
						return FormValidation.error("Authentification failed with " + sshHostname);
					}

					Session session = connection.openSession();
					session.execCommand(command);
					session.waitForCondition(ChannelCondition.EXIT_STATUS, 60000);
					if (session.getExitStatus() != 0) {
						return FormValidation.error(String.format("Commad: %s, failed on: %s", command, sshHostname));
					}
					session.close();
					connection.close();
				}
			} catch (InterruptedException e) {
				return FormValidation.error(e, e.getMessage());
			} catch (IOException e) {
				return FormValidation.error(e, e.getMessage());
			}
			return FormValidation.ok();
		}

		public FormValidation doCheckDbDriver(@QueryParameter final String dbURL, @QueryParameter final String dbDriver) {
			if (StringUtils.isBlank(dbURL)) {
				return FormValidation.ok();
			}
			if (StringUtils.isBlank(dbDriver)) {
				return FormValidation.error("Driver must be set.");
			}
			try {
				Class.forName(dbDriver);
			} catch (Exception e) {
				return FormValidation.error(e, e.getMessage());
			}
			return FormValidation.ok();
		}

		public FormValidation doCheckDbRequestFile(@QueryParameter final String dbDriver,
				@QueryParameter final String dbRequest, @QueryParameter final String dbRequestFile) {
			if (StringUtils.isBlank(dbDriver)) {
				return FormValidation.ok();
			}
			if (StringUtils.isBlank(dbRequestFile) && StringUtils.isBlank(dbRequest)) {
				return FormValidation.error("Request must be set.");
			}
			if (!StringUtils.isBlank(dbRequestFile)) {
				URL url;
				try {
					url = new URL(dbRequestFile);
					url.openConnection().getInputStream();
				} catch (Exception e) {
					return FormValidation.error(e, e.getMessage());
				}
				return FormValidation.ok();
			} else {
				if (!StringUtils.isBlank(dbRequest)) {
					return FormValidation.error("Request and Request file don't be set in same time");
				}
			}
			return FormValidation.ok();
		}
	}

	private boolean quoteValue;

	private int visibleItemCount;

	private String type;

	private String value;

	private String propertyFile;

	private String propertyKey;

	private String defaultValue;

	private String defaultPropertyFile;

	private String defaultPropertyKey;

	private String multiSelectDelimiter;

	private String command;

	private String sshUsername;

	private String sshPassword;

	private String sshHostname;

	private String sshPublicKey;

	private String dbDriver;

	private String dbURL;

	private String dbUsername;

	private String dbPassword;

	private String dbRequest;

	private String dbRequestFile;

	@DataBoundConstructor
	public ExtendedChoiceParameterDefinition(String name, String type, String value, String propertyFile,
			String propertyKey, String defaultValue, String defaultPropertyFile, String defaultPropertyKey,
			boolean quoteValue, String command, String sshUsername, String sshPassword, String sshHostname,
			String sshPublicKey, int visibleItemCount, String description, String dbURL, String dbDriver,
			String dbPassword, String dbUsername, String dbRequest, String dbRequestFile,String multiSelectDelimiter) {
		super(name, description);
		this.type = type;

		this.propertyFile = propertyFile;
		this.propertyKey = propertyKey;

		this.defaultPropertyFile = defaultPropertyFile;
		this.defaultPropertyKey = defaultPropertyKey;
		this.value = value;
		this.defaultValue = defaultValue;
		this.quoteValue = quoteValue;
		this.command = command;
		this.sshHostname = sshHostname;
		this.sshPassword = sshPassword;
		this.sshUsername = sshUsername;
		this.sshPublicKey = sshPublicKey;
		this.dbURL = dbURL;
		this.dbDriver = dbDriver;
		this.dbPassword = dbPassword;
		this.dbUsername = dbUsername;
		this.dbRequest = dbRequest;
		this.dbRequestFile = dbRequestFile;
		if (visibleItemCount == 0) {
			visibleItemCount = 5;
		}
		this.visibleItemCount = visibleItemCount;
		
		if(multiSelectDelimiter.equals("")) {
			multiSelectDelimiter = ",";
	}
		this.multiSelectDelimiter = multiSelectDelimiter;
	}

	private Map<String, Boolean> computeDefaultValueMap() {
		Map<String, Boolean> defaultValueMap = null;
		String effectiveDefaultValue = getEffectiveDefaultValue();
		if (!StringUtils.isBlank(effectiveDefaultValue)) {
			defaultValueMap = new HashMap<String, Boolean>();
			String[] defaultValues = StringUtils.split(effectiveDefaultValue, ',');
			for (String value : defaultValues) {
				defaultValueMap.put(StringUtils.trim(value), true);
			}
		}
		return defaultValueMap;
	}

	@Override
	public ParameterValue createValue(StaplerRequest request) {
		String[] requestValues = request.getParameterValues(getName());
		if (requestValues == null || requestValues.length == 0) {
			return getDefaultParameterValue();
		}
		if (PARAMETER_TYPE_TEXT_BOX.equals(type)) {
			return new ExtendedChoiceParameterValue(getName(), requestValues[0]);
		}
		else {
			String valueStr = getEffectiveValue();
			if (valueStr != null) {
				List<String> result = new ArrayList<String>();

				String[] values = valueStr.split(",");
				Set<String> valueSet = new HashSet<String>();
				for (String value : values) {
					valueSet.add(value);
				}

				for (String requestValue : requestValues) {
					if (valueSet.contains(requestValue)) {
						result.add(requestValue);
					}
				}

				return new ExtendedChoiceParameterValue(getName(), StringUtils.join(result, getMultiSelectDelimiter()));
			}
		}
		return null;
	}

	@Override
	public ParameterValue createValue(StaplerRequest request, JSONObject jO) {
		Object value = jO.get("value");
		String strValue = "";
		if (value instanceof String) {
			strValue = (String) value;
		}
		else if(value instanceof JSONArray) {
			JSONArray jsonValues = (JSONArray) value;
			if (   type.equals(PARAMETER_TYPE_MULTI_LEVEL_SINGLE_SELECT)
				  || type.equals(PARAMETER_TYPE_MULTI_LEVEL_MULTI_SELECT))
			{
				final int valuesBetweenLevels = this.value.split(",").length;
				
				Iterator it = jsonValues.iterator();
				for (int i = 1; it.hasNext(); i++)
				{
					String nextValue = it.next().toString();
					if (i % valuesBetweenLevels == 0)
					{
						if (strValue.length() > 0)
						{
							strValue += getMultiSelectDelimiter();
						}
						strValue += nextValue;
					}
				}
			}
			else
			{
				strValue = StringUtils.join(jsonValues.iterator(), getMultiSelectDelimiter());
			}
		}

		if (quoteValue) {
			strValue = "\"" + strValue + "\"";
		}
		return new ExtendedChoiceParameterValue(getName(), strValue);
	}

	@Override
	public ParameterValue getDefaultParameterValue() {
		String defaultValue = getEffectiveDefaultValue();
		if (!StringUtils.isBlank(defaultValue)) {
			if (quoteValue) {
				defaultValue = "\"" + defaultValue + "\"";
			}
			return new ExtendedChoiceParameterValue(getName(), defaultValue);
		}
		return super.getDefaultParameterValue();
	}

	// note that computeValue is not called by multiLevel.jelly
	private String computeValue(String value, String propertyFilePath, String propertyKey) {
		if (!StringUtils.isBlank(propertyFile) && !StringUtils.isBlank(propertyKey)) {
			try {

				Project project = new Project();
				Property property = new Property();
				property.setProject(project);

				File propertyFile = new File(propertyFilePath);
				if (propertyFile.exists()) {
					property.setFile(propertyFile);
				}
				else {
					URL propertyFileUrl = new URL(propertyFilePath);
					property.setUrl(propertyFileUrl);
				}
				property.execute();

				return project.getProperty(propertyKey);
			} catch (Exception e) {

			}
		} else if (!StringUtils.isBlank(value)) {
			return value;
		} else if (!StringUtils.isBlank(command)) {
			if (!StringUtils.isBlank(sshHostname)) {
				return execSSHCommand();
			} else {
				return execCommand();
			}
		} else if (!StringUtils.isBlank(getDbURL())) {
			try {
				Class.forName(getDbDriver());
				java.sql.Connection connection = DriverManager.getConnection(getDbURL(), getDbUsername(),
						getDbPassword());
				PreparedStatement preparedStatement = null;
				if (StringUtils.isBlank(getDbRequestFile())) {
					preparedStatement = connection.prepareStatement(getDbRequest());
				} else {
					URL url = new URL(getDbRequestFile());
					InputStream inputStream = url.openStream();
					StringWriter writer = new StringWriter();
					IOUtils.copy(inputStream, writer, Charset.defaultCharset().name());
					String request = writer.toString();
					writer.close();
					inputStream.close();
					preparedStatement = connection.prepareStatement(request);
				}
				ResultSet resultSet = preparedStatement.executeQuery();
				String result = null;
				while (resultSet.next()) {
					if (result == null) {
						result = resultSet.getString(1);
						continue;
					}
					result = resultSet.getString(1);
				}
				return result;
			} catch (Exception e) {
				LOG.log(Level.SEVERE, e.getMessage(), e);
				return null;
			}
		}
		return null;
	}

	private String execSSHCommand() {
		Connection connection = new Connection(sshHostname);
		Session session = null;
		InputStream stdout = null;
		BufferedReader bufferedReader = null;
		try {
			connection.connect();

			boolean isAuthenticated;
			if (!StringUtils.isBlank(sshPublicKey)) {
				isAuthenticated = connection.authenticateWithPublicKey(sshUsername, sshPublicKey.toCharArray(), null);
			} else {
				isAuthenticated = connection.authenticateWithPassword(sshUsername, sshPassword);
			}

			if (!isAuthenticated) {
				FormValidation.error("Authentification failed with " + sshHostname);
				return null;
			}

			session = connection.openSession();
			session.execCommand(command);
			stdout = new StreamGobbler(session.getStdout());
			bufferedReader = new BufferedReader(new InputStreamReader(stdout));

			String result = null;
			String line = null;
			while ((line = bufferedReader.readLine()) != null) {
				if (result == null) {
					result = line;
					continue;
				}
				result += "," + line;
			}
			session.waitForCondition(ChannelCondition.EXIT_STATUS, 60000);
			if (session.getExitStatus() != 0) {
				FormValidation.error(String.format("Commad: %s, failed on: %s", command, sshHostname));
			}
			return result;
		} catch (IOException e) {
			throw new RuntimeException(e);
		} finally {
			// FIXME potential Leak!
			try {
				if (stdout != null) {
					stdout.close();
				}
				if (bufferedReader != null) {
					bufferedReader.close();
				}
				if (session != null) {
					session.close();
				}
				if (connection != null) {
					connection.close();
				}
			} catch (IOException e) {
				throw new RuntimeException(e);
			}
		}
	}

	private String execCommand() {
		String[] envs = new String[System.getenv().size()];
		int i = 0;
		for (String key : System.getenv().keySet()) {
			envs[i] = String.format("%s=%s", key, System.getenv().get(key));
			i++;
		}
		try {
			Process process = Runtime.getRuntime().exec(command, envs);
			if (process.waitFor() != 0) {
				StringWriter writer = new StringWriter();
				IOUtils.copy(process.getErrorStream(), writer, Charset.defaultCharset().name());
				FormValidation.error(writer.toString());
				writer.close();
			} else {
				InputStreamReader inputStreamReader = new InputStreamReader(process.getInputStream());
				BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
				String result = null;
				String line;
				while ((line = bufferedReader.readLine()) != null) {
					if (result == null) {
						result = line;
					}
					result += "," + line;
				}
				return result;
			}
		} catch (IOException e) {
			throw new RuntimeException(e);
		} catch (InterruptedException e) {
			throw new RuntimeException(e);
		}
		return null;
	}

	@Override
	public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type;
	}

	public String getEffectiveDefaultValue() {
		return computeValue(defaultValue, defaultPropertyFile, defaultPropertyKey);
	}

	public String getDefaultValue() {
		return defaultValue;
	}

	public void setDefaultValue(String defaultValue) {
		this.defaultValue = defaultValue;
	}

	public String getPropertyFile() {
		return propertyFile;
	}

	public void setPropertyFile(String propertyFile) {
		this.propertyFile = propertyFile;
	}

	public String getDefaultPropertyKey() {
		return defaultPropertyKey;
	}

	public void setDefaultPropertyKey(String defaultPropertyKey) {
		this.defaultPropertyKey = defaultPropertyKey;
	}

	public String getEffectiveValue() {
		return computeValue(value, propertyFile, propertyKey);
	}
	
	private ArrayList<Integer> columnIndicesForDropDowns(String[] headerColumns)
	{
		ArrayList<Integer> columnIndicesForDropDowns = new ArrayList<Integer>();
		
		String[] dropDownNames = value.split(",");

		for (String dropDownName : dropDownNames)
		{
			for (int i = 0; i < headerColumns.length; ++i)
			{
				if (headerColumns[i].equals(dropDownName))
				{
					columnIndicesForDropDowns.add(new Integer(i));
				}
			}
		}
		
		return columnIndicesForDropDowns;
	}
	
	LinkedHashMap<String, LinkedHashSet<String>> calculateChoicesByDropdownId() throws Exception
	{
		List<String[]> fileLines =
			new CSVReader(new FileReader(propertyFile), '\t').readAll();

		if (fileLines.size() < 2)
		{
			throw new Exception("Multi level tab delimited file must have at least 2 "
							+ "lines (one for the header, and one or more for the data)");
		}

		ArrayList<Integer> columnIndicesForDropDowns =
						columnIndicesForDropDowns(fileLines.get(0));
		
		List<String[]> dataLines = fileLines.subList(1, fileLines.size());

		LinkedHashMap<String, LinkedHashSet<String>> choicesByDropdownId =
						new LinkedHashMap<String, LinkedHashSet<String>>();

		String prefix = getName() + " dropdown MultiLevelMultiSelect 0";
		choicesByDropdownId.put(prefix, new LinkedHashSet<String>());

		for (int i=0; i < columnIndicesForDropDowns.size(); ++i)
		{
			String prettyCurrentColumnName = value.split(",")[i];
			prettyCurrentColumnName = prettyCurrentColumnName.toLowerCase();
			prettyCurrentColumnName = prettyCurrentColumnName.replace("_", " ");

			for (String[] dataLine : dataLines)
			{
				String priorLevelDropdownId = prefix;
				String currentLevelDropdownId = prefix;

				int column = 0;
				for (int j=0; j <= i; ++j)
				{
					column = columnIndicesForDropDowns.get(j);

					if (j < i)
					{
						priorLevelDropdownId += " " + dataLine[column];
					}
					currentLevelDropdownId += " " + dataLine[column];
				}					
				if (i != columnIndicesForDropDowns.size() - 1)
				{
					choicesByDropdownId.put(currentLevelDropdownId, new LinkedHashSet<String>());
				}
				LinkedHashSet<String> choicesForPriorDropdown
								= choicesByDropdownId.get(priorLevelDropdownId);
				choicesForPriorDropdown.add("Select a " + prettyCurrentColumnName
																		+ "...");
				choicesForPriorDropdown.add(dataLine[column]);
			}				
		}

		return choicesByDropdownId;
	}
	
	public String getMultiLevelDropdownIds() throws Exception
	{
		String dropdownIds = new String();
		
		LinkedHashMap<String, LinkedHashSet<String>> choicesByDropdownId = 
						calculateChoicesByDropdownId();
		
		for (String id : choicesByDropdownId.keySet())
		{
			if (dropdownIds.length() > 0)
			{
				dropdownIds += ",";
			}
			dropdownIds += id;
		}
				
		return dropdownIds;
		
		/* dropdownIds is of a form like this:
		return name + " dropdown MultiLevelMultiSelect 0," 
				   // next select the source of the genome -- each genome gets a seperate dropdown id:"
				 + name + " dropdown MultiLevelMultiSelect 0 HG18,dropdown MultiLevelMultiSelect 0 ZZ23,"
				 // next select the cell type of the source -- each source gets a seperate dropdown id
				 + name + " dropdown MultiLevelMultiSelect 0 HG18 Diffuse large B-cell lymphoma, dropdown MultiLevelMultiSelect 0 HG18 Multiple Myeloma,"
				 + name + " dropdown MultiLevelMultiSelect 0 ZZ23 Neuroblastoma,"
				 // next select the name from the cell type -- each cell type gets a seperate dropdown id
				 + name + " dropdown MultiLevelMultiSelect 0 HG18 Diffuse large B-cell lymphoma LY1,"
				 + name + " dropdown MultiLevelMultiSelect 0 HG18 Multiple Myeloma MM1S,"
				 + name + " dropdown MultiLevelMultiSelect 0 ZZ23 Neuroblastoma BE2C,"
				 + name + " dropdown MultiLevelMultiSelect 0 ZZ23 Neuroblastoma SKNAS";*/
	}
	
	public Map<String, String> getChoicesByDropdownId() throws Exception
	{
		LinkedHashMap<String, LinkedHashSet<String>> choicesByDropdownId = 
			calculateChoicesByDropdownId();
		
		Map<String, String> collapsedMap = new LinkedHashMap<String, String>();
		
		for (String dropdownId : choicesByDropdownId.keySet())
		{
			String choices = new String();
			for (String choice : choicesByDropdownId.get(dropdownId))
			{
				if (choices.length() > 0)
				{
					choices += ",";
				}
				choices += choice;
			}
			
			collapsedMap.put(dropdownId, choices);
		}
				
		/* collapsedMap is of a form like this:
		collapsedMap.put(name + " dropdown MultiLevelMultiSelect 0", "Select a genome...,HG18,ZZ23");
		collapsedMap.put(name + " dropdown MultiLevelMultiSelect 0 HG18", "Select a source...,Diffuse large B-cell lymphoma,Multiple Myeloma");
		collapsedMap.put(name + " dropdown MultiLevelMultiSelect 0 ZZ23", "Select a source...,Neuroblastoma");
		collapsedMap.put(name + " dropdown MultiLevelMultiSelect 0 HG18 Diffuse large B-cell lymphoma","Select a cell type...,LY1");
		collapsedMap.put(name + " dropdown MultiLevelMultiSelect 0 HG18 Multiple Myeloma","Select a cell type...,MM1S");
		collapsedMap.put(name + " dropdown MultiLevelMultiSelect 0 ZZ23 Neuroblastoma","Select a cell type...,BE2C,SKNAS");
		collapsedMap.put(name + " dropdown MultiLevelMultiSelect 0 HG18 Diffuse large B-cell lymphoma LY1","Select a name...,LY1_BCL6_DMSO,LY1_BCL6_JQ1");
		collapsedMap.put(name + " dropdown MultiLevelMultiSelect 0 HG18 Multiple Myeloma MM1S", "Select a name...,MM1S_BRD4_150nM_JQ1,MM1S_BRD4_500nM_JQ1");
		collapsedMap.put(name + " dropdown MultiLevelMultiSelect 0 ZZ23 Neuroblastoma BE2C", "Select a name...,BE2C_BRD4");
		collapsedMap.put(name + " dropdown MultiLevelMultiSelect 0 ZZ23 Neuroblastoma SKNAS", "Select a name...,SKNAS_H3K4ME3");
		*/
		
		return collapsedMap;
	}

	public String getValue() {
		return value;
	}

	public void setValue(String value) {
		this.value = value;
	}

	public String getPropertyKey() {
		return propertyKey;
	}

	public void setPropertyKey(String propertyKey) {
		this.propertyKey = propertyKey;
	}

	public String getDefaultPropertyFile() {
		return defaultPropertyFile;
	}

	public boolean isQuoteValue() {
		return quoteValue;
	}

	public void setQuoteValue(boolean quoteValue) {
		this.quoteValue = quoteValue;
	}

	public int getVisibleItemCount() {
		return visibleItemCount;
	}

	public void setVisibleItemCount(int visibleItemCount) {
		this.visibleItemCount = visibleItemCount;
	}

	public String getMultiSelectDelimiter() {
		return this.multiSelectDelimiter;
	}
	
	public void setMultiSelectDelimiter(final String multiSelectDelimiter) {
		this.multiSelectDelimiter = multiSelectDelimiter;
	}

	public void setDefaultPropertyFile(String defaultPropertyFile) {
		this.defaultPropertyFile = defaultPropertyFile;
	}

	public Map<String, Boolean> getDefaultValueMap() {
		return computeDefaultValueMap();
	}

	public String getSshUsername() {
		return sshUsername;
	}

	public void setSshUsername(String sshUsername) {
		this.sshUsername = sshUsername;
	}

	public String getSshPassword() {
		return sshPassword;
	}

	public void setSshPassword(String sshPassword) {
		this.sshPassword = sshPassword;
	}

	public String getSshHostname() {
		return sshHostname;
	}

	public void setSshHostname(String sshHostname) {
		this.sshHostname = sshHostname;
	}

	public String getCommand() {
		return command;
	}

	public void setCommand(String command) {
		this.command = command;
	}

	public String getSshPrivateKey() {
		return sshPublicKey;
	}

	public void setSshPrivateKey(String sshPrivateKey) {
		this.sshPublicKey = sshPrivateKey;
	}

	public String getDbDriver() {
		return dbDriver;
	}

	public void setDbDriver(String dbDriver) {
		this.dbDriver = dbDriver;
	}

	public String getDbURL() {
		return dbURL;
	}

	public void setDbURL(String dbURL) {
		this.dbURL = dbURL;
	}

	public String getDbUsername() {
		return dbUsername;
	}

	public void setDbUsername(String dbUsername) {
		this.dbUsername = dbUsername;
	}

	public String getDbPassword() {
		return dbPassword;
	}

	public void setDbPassword(String dbPassword) {
		this.dbPassword = dbPassword;
	}

	public String getDbRequest() {
		return dbRequest;
	}

	public void setDbRequest(String dbRequest) {
		this.dbRequest = dbRequest;
	}

	public String getDbRequestFile() {
		return dbRequestFile;
	}

	public void setDbRequestFile(String dbRequestFile) {
		this.dbRequestFile = dbRequestFile;
	}
}
