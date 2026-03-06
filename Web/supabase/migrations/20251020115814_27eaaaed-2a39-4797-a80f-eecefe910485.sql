-- Remove created_at and updated_at columns from events table
ALTER TABLE public.events DROP COLUMN created_at;
ALTER TABLE public.events DROP COLUMN updated_at;

-- Remove map_image_url since we'll use dynamic maps
ALTER TABLE public.events DROP COLUMN map_image_url;

-- Drop the trigger for updated_at since we removed the column
DROP TRIGGER IF EXISTS update_events_updated_at ON public.events;

-- Create storage bucket for event background images
INSERT INTO storage.buckets (id, name, public) 
VALUES ('event-images', 'event-images', true);

-- Storage policies for event images
CREATE POLICY "Event images are publicly accessible"
ON storage.objects FOR SELECT
USING (bucket_id = 'event-images');

CREATE POLICY "Authenticated users can upload event images"
ON storage.objects FOR INSERT
WITH CHECK (
  bucket_id = 'event-images' 
  AND auth.role() = 'authenticated'
);

CREATE POLICY "Authenticated users can update event images"
ON storage.objects FOR UPDATE
USING (
  bucket_id = 'event-images' 
  AND auth.role() = 'authenticated'
);

CREATE POLICY "Authenticated users can delete event images"
ON storage.objects FOR DELETE
USING (
  bucket_id = 'event-images' 
  AND auth.role() = 'authenticated'
);