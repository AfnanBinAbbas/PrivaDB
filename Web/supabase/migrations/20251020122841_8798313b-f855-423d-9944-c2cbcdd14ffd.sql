-- Storage policies for event-images bucket
-- Ensure public read and authenticated write/update

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies 
    WHERE schemaname = 'storage' AND tablename = 'objects' AND policyname = 'Event images public read'
  ) THEN
    CREATE POLICY "Event images public read"
    ON storage.objects
    FOR SELECT
    USING (bucket_id = 'event-images');
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies 
    WHERE schemaname = 'storage' AND tablename = 'objects' AND policyname = 'Event images upload (authenticated)'
  ) THEN
    CREATE POLICY "Event images upload (authenticated)"
    ON storage.objects
    FOR INSERT
    TO authenticated
    WITH CHECK (bucket_id = 'event-images');
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies 
    WHERE schemaname = 'storage' AND tablename = 'objects' AND policyname = 'Event images update (authenticated)'
  ) THEN
    CREATE POLICY "Event images update (authenticated)"
    ON storage.objects
    FOR UPDATE
    TO authenticated
    USING (bucket_id = 'event-images')
    WITH CHECK (bucket_id = 'event-images');
  END IF;
END $$;