-- Allow event creators to view registrations for their events
CREATE POLICY "Event creators can view registrations"
ON public.event_registrations
FOR SELECT
TO authenticated
USING (
  EXISTS (
    SELECT 1
    FROM public.events
    WHERE events.id = event_registrations.event_id
    AND events.created_by = auth.uid()
  )
);