import React, { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import FileDropzone from "../components/common/FileDropzone";
import Footer from "../components/common/Footer";
import SideNav from "../components/SideNav";
import TransformationLimitModal from "../components/TransformationLimitModal";
import { useAuth } from "../contexts/useAuth";
import { tokenStorage } from "../utils/tokenStorage";
import DestinationTemplateUpload from "../components/DestinationTemplateUpload";

function TransformerPage() {
	const { user } = useAuth(); // Get user to check if logged in
	const navigate = useNavigate();
	const [sourceFiles, setSourceFiles] = useState([]);
	const [destinationXml, setDestinationXml] = useState(null);
	const [mappingJson, setMappingJson] = useState(null);
	const [_xsdSchema, setXsdSchema] = useState(null); // For future XSD validation

	const [removeEmptyTags, setRemoveEmptyTags] = useState(true);
	const [useXPath, setUseXPath] = useState(false);

	const [inputXml, setInputXml] = useState("");
	const [outputXml, setOutputXml] = useState("");
	const [status, setStatus] = useState("Ready");
	const [sourceCount, setSourceCount] = useState(0);

	// Usage tracking state
	const [usageInfo, setUsageInfo] = useState({
		used: 0,
		limit: 0,
		remaining: 0,
		subscriptionLevel: "free",
	});
	const [showLimitModal, setShowLimitModal] = useState(false);

	const handleTransform = async () => {
		if (sourceFiles.length === 0 || !destinationXml || !mappingJson) {
			alert("Please provide Source XML, Destination Template, and Mapping JSON.");
			return;
		}

		// Check if user is authenticated - transformation requires login
		const token = tokenStorage.getToken();
		if (!token || !user) {
			alert("Please log in to use the transformation tool. Free accounts get 10 transformations per day!");
			return;
		}

		setStatus("Transforming...");
		try {
			const endpoint = "/api/transform";
			const headers = {
				"Content-Type": "application/json",
				Authorization: `Bearer ${token}`,
			};

			console.log(`[Transform] Using endpoint: ${endpoint} (authenticated)`);

			const response = await fetch(endpoint, {
				method: "POST",
				headers: headers,
				body: JSON.stringify({
					sourceXml: sourceFiles[0].content,
					destinationXml: destinationXml.content,
					mappingJson: JSON.parse(mappingJson.content),
					removeEmptyTags: removeEmptyTags,
				}),
			});

			// Handle rate limit errors (429)
			if (response.status === 429) {
				const errorData = await response.json();
				console.log("Rate limit response:", errorData);

				// Handle both possible response formats
				const usage = errorData.usage || errorData.details || {};

				setUsageInfo({
					used: usage.used || 0,
					limit: usage.limit || 10,
					remaining: usage.remaining || 0,
					subscriptionLevel: usage.subscription_level || errorData.subscription_level || "free",
				});
				setShowLimitModal(true);
				setStatus("Rate limit exceeded");
				return;
			}

			// Handle authentication errors
			if (response.status === 401) {
				alert("Your session has expired. Please log in again.");
				return;
			}

			if (!response.ok) {
				const errorText = await response.text();
				throw new Error(`Server error: ${response.status} - ${errorText}`);
			}

			// Extract usage info from headers
			const usageLimit = parseInt(response.headers.get("X-Usage-Limit") || "0");
			const usageCount = parseInt(response.headers.get("X-Usage-Count") || "0");
			const usageRemaining = parseInt(response.headers.get("X-Usage-Remaining") || "0");
			const subscriptionLevel = response.headers.get("X-Subscription-Level") || "free";

			// Update usage info state
			setUsageInfo({
				used: usageCount,
				limit: usageLimit,
				remaining: usageRemaining,
				subscriptionLevel: subscriptionLevel,
			});

			const transformed = await response.text();
			setOutputXml(transformed);
			setStatus(`Transformation successful! (${usageCount}/${usageLimit} used today)`);
		} catch (err) {
			alert("Error: " + err.message);
			setStatus("Error during transformation.");
		}
	};

	const handleCopy = () => {
		if (outputXml) {
			navigator.clipboard.writeText(outputXml);
			setStatus("Copied to clipboard!");
			setTimeout(() => setStatus("Ready"), 2000);
		}
	};

	const handleUpgrade = () => {
		setShowLimitModal(false);
		navigate("/pricing");
	};

	return (
		<div>
			<div className="flex flex-row bg-gray-50">
				<SideNav />

				<div className="mx-12 w-full max-w-7xl">
					{/* Transformation Limit Modal */}
					<TransformationLimitModal
						show={showLimitModal}
						subscriptionLevel={usageInfo.subscriptionLevel}
						used={usageInfo.used}
						limit={usageInfo.limit}
						remaining={usageInfo.remaining}
						onClose={() => setShowLimitModal(false)}
						onUpgrade={handleUpgrade}
					/>
					<div className="my-15">
						<div className="flex flex-col gap-4">
							<h1 className="text-2xl text-gray-700 font-semibold">Transformer</h1>
							<p className="text-gray-700">
								Upload your XML files, template, and mapping file, adjust any settings you need, run the transformation,
								then preview and download the final XML or ZIP file.
							</p>
						</div>
					</div>

					<DestinationTemplateUpload></DestinationTemplateUpload>

					<div className="">
						<div className="upload-section">
							<div className="bg-gray-100 border-2 border-gray-200 p-4 rounded-2xl w-full max-w-7xl">
								<FileDropzone
									onFileSelect={(files) => {
										setSourceFiles(files);
										setSourceCount(files.length);
										if (files.length > 0) setInputXml(files[0].content);
									}}
								>
									<svg width="36" height="36" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
										<path
											d="M20.5 10.19H17.61C15.24 10.19 13.31 8.26 13.31 5.89V3C13.31 2.45 12.86 2 12.31 2H8.07C4.99 2 2.5 4 2.5 7.57V16.43C2.5 20 4.99 22 8.07 22H15.93C19.01 22 21.5 20 21.5 16.43V11.19C21.5 10.64 21.05 10.19 20.5 10.19ZM11.53 13.53C11.38 13.68 11.19 13.75 11 13.75C10.81 13.75 10.62 13.68 10.47 13.53L9.75 12.81V17C9.75 17.41 9.41 17.75 9 17.75C8.59 17.75 8.25 17.41 8.25 17V12.81L7.53 13.53C7.24 13.82 6.76 13.82 6.47 13.53C6.18 13.24 6.18 12.76 6.47 12.47L8.47 10.47C8.54 10.41 8.61 10.36 8.69 10.32C8.71 10.31 8.74 10.3 8.76 10.29C8.82 10.27 8.88 10.26 8.95 10.25C8.98 10.25 9 10.25 9.03 10.25C9.11 10.25 9.19 10.27 9.27 10.3C9.28 10.3 9.28 10.3 9.29 10.3C9.37 10.33 9.45 10.39 9.51 10.45C9.52 10.46 9.53 10.46 9.53 10.47L11.53 12.47C11.82 12.76 11.82 13.24 11.53 13.53Z"
											fill="#64748B"
										/>
										<path
											w
											d="M17.43 8.80999C18.38 8.81999 19.7 8.81999 20.83 8.81999C21.4 8.81999 21.7 8.14999 21.3 7.74999C19.86 6.29999 17.28 3.68999 15.8 2.20999C15.39 1.79999 14.68 2.07999 14.68 2.64999V6.13999C14.68 7.59999 15.92 8.80999 17.43 8.80999Z"
											fill="#64748B"
										/>
									</svg>
									<h3 className="text-xl">Upload or Drag and drop XML or ZIP files</h3>
									<span className="file-count">
										Uploaded: <span id="sourceCount">{sourceCount}</span>
									</span>
								</FileDropzone>
							</div>

							<div className="bg-indigo-100 border-2 border-indigo-200 p-4 rounded-xl w-full max-w-7xl hover:border-indigo-400 hover:cursor-pointer">
								<FileDropzone onFileSelect={(files) => setDestinationXml(files[0])}>
									<svg width="36" height="36" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
										<path
											d="M20.5 10.19H17.61C15.24 10.19 13.31 8.26 13.31 5.89V3C13.31 2.45 12.86 2 12.31 2H8.07C4.99 2 2.5 4 2.5 7.57V16.43C2.5 20 4.99 22 8.07 22H15.93C19.01 22 21.5 20 21.5 16.43V11.19C21.5 10.64 21.05 10.19 20.5 10.19ZM11.53 13.53C11.38 13.68 11.19 13.75 11 13.75C10.81 13.75 10.62 13.68 10.47 13.53L9.75 12.81V17C9.75 17.41 9.41 17.75 9 17.75C8.59 17.75 8.25 17.41 8.25 17V12.81L7.53 13.53C7.24 13.82 6.76 13.82 6.47 13.53C6.18 13.24 6.18 12.76 6.47 12.47L8.47 10.47C8.54 10.41 8.61 10.36 8.69 10.32C8.71 10.31 8.74 10.3 8.76 10.29C8.82 10.27 8.88 10.26 8.95 10.25C8.98 10.25 9 10.25 9.03 10.25C9.11 10.25 9.19 10.27 9.27 10.3C9.28 10.3 9.28 10.3 9.29 10.3C9.37 10.33 9.45 10.39 9.51 10.45C9.52 10.46 9.53 10.46 9.53 10.47L11.53 12.47C11.82 12.76 11.82 13.24 11.53 13.53Z"
											fill="#64748B"
										/>
										<path
											d="M17.43 8.80999C18.38 8.81999 19.7 8.81999 20.83 8.81999C21.4 8.81999 21.7 8.14999 21.3 7.74999C19.86 6.29999 17.28 3.68999 15.8 2.20999C15.39 1.79999 14.68 2.07999 14.68 2.64999V6.13999C14.68 7.59999 15.92 8.80999 17.43 8.80999Z"
											fill="#64748B"
										/>
									</svg>
									Destination Template
									<h3 className="text-xl">Drop a single XML Template</h3>
									<span className="file-count">
										Selected: <span id="sourceCount">{sourceCount}</span>
									</span>
								</FileDropzone>
							</div>

							<FileDropzone onFileSelect={(files) => setXsdSchema(files[0])}>
								<div className="icon">
									<svg width="48" height="48" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
										<path
											d="M14 2H6C5.46957 2 4.96086 2.21071 4.58579 2.58579C4.21071 2.96086 4 3.46957 4 4V20C4 20.5304 4.21071 21.0391 4.58579 21.4142C4.96086 21.7893 5.46957 22 6 22H18C18.5304 22 19.0391 21.7893 19.4142 21.4142C19.7893 21.0391 20 20.5304 20 20V8L14 2Z"
											stroke="currentColor"
											strokeWidth="2"
											strokeLinecap="round"
											strokeLinejoin="round"
										/>
										<path
											d="M14 2V8H20"
											stroke="currentColor"
											strokeWidth="2"
											strokeLinecap="round"
											strokeLinejoin="round"
										/>
										<path
											d="M9 15L11 17L16 12"
											stroke="currentColor"
											strokeWidth="2"
											strokeLinecap="round"
											strokeLinejoin="round"
										/>
									</svg>
								</div>
								<h3>XSD Schema</h3>
								<p>Drop XSD for output validation (Optional)</p>
							</FileDropzone>

							<FileDropzone onFileSelect={(files) => setMappingJson(files[0])}>
								<div className="icon">
									<svg width="48" height="48" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
										<path
											d="M14 2H6C5.46957 2 4.96086 2.21071 4.58579 2.58579C4.21071 2.96086 4 3.46957 4 4V20C4 20.5304 4.21071 21.0391 4.58579 21.4142C4.96086 21.7893 5.46957 22 6 22H18C18.5304 22 19.0391 21.7893 19.4142 21.4142C19.7893 21.0391 20 20.5304 20 20V8L14 2Z"
											stroke="currentColor"
											strokeWidth="2"
											strokeLinecap="round"
											strokeLinejoin="round"
										/>
										<path
											d="M14 2V8H20"
											stroke="currentColor"
											strokeWidth="2"
											strokeLinecap="round"
											strokeLinejoin="round"
										/>
										<path
											d="M8 13L10 15L8 17"
											stroke="currentColor"
											strokeWidth="2"
											strokeLinecap="round"
											strokeLinejoin="round"
										/>
										<path
											d="M16 13L14 15L16 17"
											stroke="currentColor"
											strokeWidth="2"
											strokeLinecap="round"
											strokeLinejoin="round"
										/>
									</svg>
								</div>
								<h3>Mapping JSON</h3>
								<p>Drop your mapping file</p>
							</FileDropzone>
						</div>

						<section className="flex flex-col gap-4">
							<h3 className="text-xl">Input XML Preview</h3>
							<textarea
								id="inputXml"
								className="w-full border-2 p-4 rounded-lg h-48 border-gray-300 bg-gray-50 hover:cursor-not-allowed text-gray-600"
								readOnly
								value={inputXml}
							></textarea>
						</section>

						<div className="config-card">
							<div style={{ display: "flex", alignItems: "center", gap: "1rem" }}>
								<div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
									<input
										type="checkbox"
										id="useXPathCheckbox"
										className="checkbox"
										checked={useXPath}
										onChange={(e) => setUseXPath(e.target.checked)}
									/>
									<label htmlFor="useXPathCheckbox" style={{ fontSize: "0.875rem", cursor: "pointer" }}>
										Enable XPath evaluation
										<abbr title="Use XPath expressions in your JSON mapping for advanced matching." className="tooltip">
											&#9432;
										</abbr>
									</label>
								</div>
								<div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
									<input
										type="checkbox"
										id="removeEmptyTagsCheckbox"
										className="checkbox"
										checked={removeEmptyTags}
										onChange={(e) => setRemoveEmptyTags(e.target.checked)}
									/>
									<label htmlFor="removeEmptyTagsCheckbox" style={{ fontSize: "0.875rem", cursor: "pointer" }}>
										Remove Empty Tags
										<abbr
											title="Tick this to remove empty XML tags from the output. Cargowise requires this to pass schema validation."
											className="tooltip"
										>
											&#9432;
										</abbr>
									</label>
								</div>
							</div>
							<div className="action-buttons">
								<button
									id="transformBtn"
									className="bg-indigo-600 px-4 py-2 rounded-lg font-semibold text-white"
									onClick={handleTransform}
								>
									Transform
								</button>
								<Link to="/editor" className="secondary-btn" role="button">
									Create / Edit Mapping
								</Link>
							</div>
							<div id="actions" className="status-message">
								{status}
							</div>
						</div>

						<section className="flex flex-col gap-4">
							<h3 className="text-xl">Output XML Preview</h3>
							<textarea
								id="outputXml"
								className="w-full border-2 p-4 rounded-lg h-48 border-gray-300"
								readOnly
								value={outputXml}
								placeholder="Output XML"
							></textarea>
							<div className="flex gap-4">
								<button
									className="bg-indigo-100 px-4 py-2 rounded-lg font-semibold text-indigo-600 w-fit"
									onClick={handleCopy}
								>
									Copy XML
								</button>
								<a
									id="downloadLink"
									className="bg-indigo-600 px-4 py-2 rounded-lg font-semibold text-white w-fit"
									href={"data:text/xml;charset=utf-8," + encodeURIComponent(outputXml)}
									download="transformed.xml"
								>
									Download XML file
								</a>
							</div>
						</section>
					</div>
				</div>
			</div>
			<Footer />
		</div>
	);
}

export default TransformerPage;
