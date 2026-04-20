data "aws_caller_identity" "current" {}

resource "aws_s3_bucket" "logs_archive" {
  bucket = "sqli-project-logs-${data.aws_caller_identity.current.account_id}"

  # Necessary to prevent accidental bucket deletion with objects in it if testing
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "logs_archive" {
  bucket = aws_s3_bucket.logs_archive.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "logs_archive" {
  bucket = aws_s3_bucket.logs_archive.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs_archive" {
  bucket = aws_s3_bucket.logs_archive.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "logs_archive" {
  bucket = aws_s3_bucket.logs_archive.id

  rule {
    id     = "sqli-logs-archival"
    status = "Enabled"

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = 365
    }
  }
}

# reviewed
