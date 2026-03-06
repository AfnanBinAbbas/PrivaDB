-- Add created_by column to events table to track who created each event
ALTER TABLE public.events ADD COLUMN created_by UUID REFERENCES auth.users(id) ON DELETE SET NULL;

-- Create event_registrations table to track user registrations
CREATE TABLE public.event_registrations (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  event_id UUID NOT NULL REFERENCES public.events(id) ON DELETE CASCADE,
  registered_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  UNIQUE(user_id, event_id)
);

-- Enable Row Level Security
ALTER TABLE public.event_registrations ENABLE ROW LEVEL SECURITY;

-- RLS Policies for event_registrations
CREATE POLICY "Users can view their own registrations"
ON public.event_registrations
FOR SELECT
USING (auth.uid() = user_id);

CREATE POLICY "Users can create their own registrations"
ON public.event_registrations
FOR INSERT
WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can delete their own registrations"
ON public.event_registrations
FOR DELETE
USING (auth.uid() = user_id);

-- Update events RLS policies to allow users to see their own created events
CREATE POLICY "Users can view their own created events"
ON public.events
FOR SELECT
USING (auth.uid() = created_by OR created_by IS NULL);

-- Update events insert policy to set created_by
DROP POLICY IF EXISTS "Authenticated users can insert events" ON public.events;
CREATE POLICY "Authenticated users can insert events"
ON public.events
FOR INSERT
WITH CHECK (auth.uid() = created_by);

-- Update events update policy  
DROP POLICY IF EXISTS "Authenticated users can update events" ON public.events;
CREATE POLICY "Users can update their own events"
ON public.events
FOR UPDATE
USING (auth.uid() = created_by);

-- Update events delete policy
DROP POLICY IF EXISTS "Authenticated users can delete events" ON public.events;
CREATE POLICY "Users can delete their own events"
ON public.events
FOR DELETE
USING (auth.uid() = created_by);