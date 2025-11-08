/**
 * ML Inference Wrapper
 * Node.js service to execute Python ML inference from Lambda
 */

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs').promises;
const os = require('os');

class MLInferenceService {
  constructor() {
    this.pythonPath = 'python3';
    this.mlDir = path.join(__dirname, '..', 'ml');
    this.inferenceScript = path.join(this.mlDir, 'inference_service.py');
    this.timeout = 60000; // 60 seconds
  }

  /**
   * Extract invoice data using LayoutLMv3 + LoRA
   * @param {string} imagePath - Absolute path to invoice image/PDF
   * @param {object} options - Extraction options
   * @returns {Promise<object>} Extracted fields with confidence scores
   */
  async extractInvoiceData(imagePath, options = {}) {
    try {
      // Verify image exists
      await fs.access(imagePath);

      // Create temp output file
      const tempDir = os.tmpdir();
      const outputFile = path.join(tempDir, `ml_output_${Date.now()}.json`);

      // Build command arguments
      const args = [
        this.inferenceScript,
        '--image', imagePath,
        '--output', outputFile
      ];

      if (options.adapterPath) {
        args.push('--adapter', options.adapterPath);
      }

      // Execute Python inference
      const result = await this._executePython(args);

      // Read output file
      const outputData = await fs.readFile(outputFile, 'utf-8');
      const extractedData = JSON.parse(outputData);

      // Clean up temp file
      await fs.unlink(outputFile).catch(() => {});

      return {
        success: true,
        data: extractedData,
        metadata: {
          executionTime: result.executionTime,
          modelVersion: extractedData.metadata?.model_version || 'unknown'
        }
      };

    } catch (error) {
      console.error('ML extraction failed:', error);
      return {
        success: false,
        error: error.message,
        data: null
      };
    }
  }

  /**
   * Execute Python script and capture output
   * @private
   */
  _executePython(args) {
    return new Promise((resolve, reject) => {
      const startTime = Date.now();
      let stdout = '';
      let stderr = '';

      const pythonProcess = spawn(this.pythonPath, args, {
        cwd: this.mlDir,
        env: {
          ...process.env,
          PYTHONUNBUFFERED: '1'
        }
      });

      // Capture stdout
      pythonProcess.stdout.on('data', (data) => {
        stdout += data.toString();
      });

      // Capture stderr
      pythonProcess.stderr.on('data', (data) => {
        stderr += data.toString();
      });

      // Handle process completion
      pythonProcess.on('close', (code) => {
        const executionTime = Date.now() - startTime;

        if (code === 0) {
          resolve({
            stdout,
            stderr,
            exitCode: code,
            executionTime
          });
        } else {
          reject(new Error(
            `Python process exited with code ${code}\n` +
            `STDERR: ${stderr}\n` +
            `STDOUT: ${stdout}`
          ));
        }
      });

      // Handle errors
      pythonProcess.on('error', (error) => {
        reject(new Error(`Failed to start Python process: ${error.message}`));
      });

      // Set timeout
      const timeoutId = setTimeout(() => {
        pythonProcess.kill('SIGTERM');
        reject(new Error(`Python process timed out after ${this.timeout}ms`));
      }, this.timeout);

      pythonProcess.on('close', () => {
        clearTimeout(timeoutId);
      });
    });
  }

  /**
   * Check if ML service is available
   * @returns {Promise<boolean>}
   */
  async healthCheck() {
    try {
      // Verify Python is available
      await this._executePython(['--version']);

      // Verify inference script exists
      await fs.access(this.inferenceScript);

      // Verify adapters directory exists
      const adaptersDir = path.join(this.mlDir, 'adapters');
      const adapterStats = await fs.stat(adaptersDir);
      
      if (!adapterStats.isDirectory()) {
        throw new Error('Adapters directory not found');
      }

      return true;
    } catch (error) {
      console.error('ML health check failed:', error);
      return false;
    }
  }

  /**
   * Get available adapter versions
   * @returns {Promise<array>} List of adapter directories
   */
  async getAvailableAdapters() {
    try {
      const adaptersDir = path.join(this.mlDir, 'adapters');
      const entries = await fs.readdir(adaptersDir, { withFileTypes: true });
      
      const adapters = entries
        .filter(entry => entry.isDirectory())
        .filter(entry => entry.name.startsWith('adapter_'))
        .map(entry => ({
          name: entry.name,
          path: path.join(adaptersDir, entry.name),
          timestamp: entry.name.replace('adapter_', '')
        }))
        .sort((a, b) => b.timestamp.localeCompare(a.timestamp));

      return adapters;
    } catch (error) {
      console.error('Failed to list adapters:', error);
      return [];
    }
  }

  /**
   * Format extracted data for database storage
   * @param {object} mlOutput - Raw ML output
   * @returns {object} Formatted data for DB
   */
  formatForDatabase(mlOutput) {
    const formatted = {
      // Invoice header fields
      invoiceNumber: mlOutput.invoice_number?.value || null,
      invoiceDate: mlOutput.date?.value || null,
      total: mlOutput.total?.value || null,
      vat: mlOutput.vat?.value || null,
      currency: mlOutput.currency?.value || null,
      incoterms: mlOutput.incoterms?.value || null,

      // Seller information
      seller: {
        name: mlOutput.seller_name?.value || null,
        address: mlOutput.seller_address?.value || null,
        confidence: this._averageConfidence([
          mlOutput.seller_name,
          mlOutput.seller_address
        ])
      },

      // Buyer information
      buyer: {
        name: mlOutput.buyer_name?.value || null,
        address: mlOutput.buyer_address?.value || null,
        confidence: this._averageConfidence([
          mlOutput.buyer_name,
          mlOutput.buyer_address
        ])
      },

      // Line items (if present)
      lineItems: this._extractLineItems(mlOutput),

      // Overall confidence
      confidence: this._calculateOverallConfidence(mlOutput),

      // Raw ML output (for debugging)
      rawExtraction: mlOutput
    };

    return formatted;
  }

  /**
   * Extract line items from ML output
   * @private
   */
  _extractLineItems(mlOutput) {
    const items = [];
    
    // Group by item index (e.g., item_description_1, item_quantity_1)
    const itemGroups = {};
    
    Object.keys(mlOutput).forEach(key => {
      const match = key.match(/^item_(\w+)_(\d+)$/);
      if (match) {
        const [, fieldType, index] = match;
        if (!itemGroups[index]) {
          itemGroups[index] = {};
        }
        itemGroups[index][fieldType] = mlOutput[key];
      }
    });

    // Convert to array
    Object.keys(itemGroups).forEach(index => {
      const item = itemGroups[index];
      items.push({
        description: item.description?.value || null,
        quantity: item.quantity?.value || null,
        price: item.price?.value || null,
        hsCode: item.hs_code?.value || null,
        confidence: this._averageConfidence(Object.values(item))
      });
    });

    return items;
  }

  /**
   * Calculate average confidence from fields
   * @private
   */
  _averageConfidence(fields) {
    const confidences = fields
      .filter(f => f && typeof f.confidence === 'number')
      .map(f => f.confidence);
    
    if (confidences.length === 0) return 0;
    
    return confidences.reduce((sum, c) => sum + c, 0) / confidences.length;
  }

  /**
   * Calculate overall extraction confidence
   * @private
   */
  _calculateOverallConfidence(mlOutput) {
    const allFields = Object.values(mlOutput)
      .filter(field => typeof field === 'object' && field !== null)
      .filter(field => typeof field.confidence === 'number');
    
    return this._averageConfidence(allFields);
  }
}

// Export singleton instance
module.exports = new MLInferenceService();
