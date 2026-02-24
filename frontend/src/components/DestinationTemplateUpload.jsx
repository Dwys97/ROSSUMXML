import React from "react";

/**
 * DestinationTemplateUpload Component
 *
 * Props:
 * - onFileSelect: function(files) - Callback when file is selected
 * - isDragActive: boolean - Whether drag is active (optional)
 */

function DestinationTemplateUpload({ onFileSelect, isDragActive = false }) {
	const handleDragOver = (e) => {
		e.preventDefault();
		e.stopPropagation();
	};

	const handleDragLeave = (e) => {
		e.preventDefault();
		e.stopPropagation();
	};

	const handleDrop = (e) => {
		e.preventDefault();
		e.stopPropagation();
		if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
			const files = Array.from(e.dataTransfer.files);
			onFileSelect(files);
		}
	};

	const handleFileInput = (e) => {
		if (e.target.files && e.target.files.length > 0) {
			const files = Array.from(e.target.files);
			onFileSelect(files);
		}
	};

	return (
		<div className="flex flex-col gap-6">
			{/* Label */}
			<p className="font-sans font-medium text-lg leading-7 text-slate-700">Upload your destination template</p>

			{/* Upload Area */}
			<label
				onDragOver={handleDragOver}
				onDragLeave={handleDragLeave}
				onDrop={handleDrop}
				className={`flex gap-4 items-center justify-center px-6 py-5 rounded border cursor-pointer transition-all ${
					isDragActive
						? "bg-slate-300 border-slate-400"
						: "bg-slate-200 border-slate-300 hover:bg-slate-250 hover:border-slate-350"
				}`}
			>
				{/* Document Upload Icon */}
				<svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" className="shrink-0">
					<path
						d="M9 13.75c.41 0 .75.34.75.75v4c0 .41-.34.75-.75.75s-.75-.34-.75-.75v-4c0-.41.34-.75.75-.75zm6-4c.41 0 .75.34.75.75v8c0 .41-.34.75-.75.75s-.75-.34-.75-.75v-8c0-.41.34-.75.75-.75zm-3-6C7.46 3.75 6 5.21 6 7v10c0 1.66 1.34 3 3 3h6c1.66 0 3-1.34 3-3V7c0-1.79-1.46-3.25-3.25-3.25H12.75V2h-1.5v1.75H12zm0 1.5h4c.69 0 1.25.56 1.25 1.25v10c0 .69-.56 1.25-1.25 1.25H9c-.69 0-1.25-.56-1.25-1.25V7c0-.69.56-1.25 1.25-1.25z"
						fill="currentColor"
						className="text-slate-700"
					/>
					<path
						d="M12 10c-.41 0-.75.34-.75.75v3.5c0 .41.34.75.75.75s.75-.34.75-.75v-3.5c0-.41-.34-.75-.75-.75z"
						fill="currentColor"
						className="text-slate-700"
					/>
				</svg>

				<div className="flex flex-col">
					<p className="font-sans font-light text-base leading-6 text-slate-700">Drop XML file here</p>
				</div>

				{/* Hidden file input */}
				<input type="file" onChange={handleFileInput} className="hidden" accept=".xml" aria-label="Upload XML file" />
			</label>
		</div>
	);
}

export default DestinationTemplateUpload;
