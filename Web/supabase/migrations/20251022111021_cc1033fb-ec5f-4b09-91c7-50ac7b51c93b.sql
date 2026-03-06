-- Fix Issue 1: Make created_by NOT NULL and update RLS policies
-- Delete orphaned events with NULL created_by (these are legacy/test data)
DELETE FROM public.events WHERE created_by IS NULL;

-- Now make created_by NOT NULL with default
ALTER TABLE public.events 
ALTER COLUMN created_by SET DEFAULT auth.uid(),
ALTER COLUMN created_by SET NOT NULL;

-- Drop the problematic SELECT policy that allows NULL owners
DROP POLICY IF EXISTS "Users can view their own created events" ON public.events;

-- Fix Issue 2: Add/update storage policies for event-images bucket
-- Drop existing policies if they exist, then recreate with proper restrictions
DROP POLICY IF EXISTS "Authenticated users can upload event images" ON storage.objects;
DROP POLICY IF EXISTS "Users can update their own event images" ON storage.objects;
DROP POLICY IF EXISTS "Users can delete their own event images" ON storage.objects;
DROP POLICY IF EXISTS "Anyone can view event images" ON storage.objects;

-- Restrict who can upload files (only authenticated users, only images, organized by user ID)
CREATE POLICY "Authenticated users can upload event images"
ON storage.objects
FOR INSERT
TO authenticated
WITH CHECK (
  bucket_id = 'event-images' 
  AND (storage.foldername(name))[1] = auth.uid()::text
  AND (LOWER(storage.extension(name)) IN ('jpg', 'jpeg', 'png', 'gif', 'webp'))
);

-- Allow users to update their own uploads
CREATE POLICY "Users can update their own event images"
ON storage.objects
FOR UPDATE
TO authenticated
USING (
  bucket_id = 'event-images' 
  AND (storage.foldername(name))[1] = auth.uid()::text
)
WITH CHECK (
  bucket_id = 'event-images' 
  AND (storage.foldername(name))[1] = auth.uid()::text
);

-- Allow users to delete their own uploads
CREATE POLICY "Users can delete their own event images"
ON storage.objects
FOR DELETE
TO authenticated
USING (
  bucket_id = 'event-images' 
  AND (storage.foldername(name))[1] = auth.uid()::text
);

-- Everyone can view event images (bucket is public)
CREATE POLICY "Anyone can view event images"
ON storage.objects
FOR SELECT
TO public
USING (bucket_id = 'event-images');