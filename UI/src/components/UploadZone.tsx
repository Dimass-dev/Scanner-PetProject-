import { useState, useCallback } from 'react';
import './UploadZone.css';

interface UploadZoneProps {
  onFileSelect: (file: File) => void;
  isLoading: boolean;
}

const MAX_FILE_SIZE = 100 * 1024 * 1024; // 100 MB
const MAX_ARCHIVE_SIZE = 200 * 1024 * 1024; // 200 MB
const ACCEPTED_EXTENSIONS = ['.exe', '.dll', '.sys', '.zip'];

export function UploadZone({ onFileSelect, isLoading }: UploadZoneProps) {
  const [isDragging, setIsDragging] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const validateFile = useCallback((file: File): string | null => {
    const ext = file.name.toLowerCase().match(/\.[^.]+$/)?.[0];

    if (!ext || !ACCEPTED_EXTENSIONS.includes(ext)) {
      return `Invalid file type. Accepted: ${ACCEPTED_EXTENSIONS.join(', ')}`;
    }

    const maxSize = ext === '.zip' ? MAX_ARCHIVE_SIZE : MAX_FILE_SIZE;
    if (file.size > maxSize) {
      const maxMB = Math.floor(maxSize / (1024 * 1024));
      return `File too large (max ${maxMB} MB)`;
    }

    return null;
  }, []);

  const handleFile = useCallback((file: File) => {
    const validationError = validateFile(file);
    if (validationError) {
      setError(validationError);
      return;
    }

    setError(null);
    onFileSelect(file);
  }, [validateFile, onFileSelect]);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (!isLoading) {
      setIsDragging(true);
    }
  }, [isLoading]);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);

    if (isLoading) return;

    const files = e.dataTransfer.files;
    if (files.length > 0) {
      handleFile(files[0]);
    }
  }, [isLoading, handleFile]);

  const handleFileInput = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (files && files.length > 0) {
      handleFile(files[0]);
    }
    e.target.value = '';
  }, [handleFile]);

  return (
    <div className="upload-zone-container">
      <div
        className={`upload-zone ${isDragging ? 'dragging' : ''} ${isLoading ? 'disabled' : ''}`}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        role="region"
        aria-label="File upload"
        aria-describedby="upload-help"
        aria-busy={isLoading}
        aria-disabled={isLoading}
      >
        <div className="upload-icon" aria-hidden="true">📁</div>
        <div className="upload-text">
          {isLoading ? (
            <p role="status" aria-live="polite">Scanning...</p>
          ) : (
            <>
              <p className="primary">Drag and drop a file here</p>
              <p className="secondary">or</p>
              <label className="file-input-label">
                <input
                  type="file"
                  onChange={handleFileInput}
                  accept=".exe,.dll,.sys,.zip"
                  disabled={isLoading}
                  className="file-input"
                  aria-label="Choose a PE file or ZIP archive"
                />
                <span className="button">Choose File</span>
              </label>
            </>
          )}
        </div>
        <div className="upload-info" id="upload-help">
          <p>Accepted: .exe, .dll, .sys, .zip</p>
          <p>Max size: 100 MB (files) / 200 MB (archives)</p>
        </div>
      </div>
      {error && (
        <div className="upload-error" role="alert">
          <span className="error-icon" aria-hidden="true">⚠️</span>
          <span>{error}</span>
        </div>
      )}
    </div>
  );
}
