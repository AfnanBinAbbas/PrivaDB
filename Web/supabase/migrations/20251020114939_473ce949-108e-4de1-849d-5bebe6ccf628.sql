-- Create events table
CREATE TABLE public.events (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  title TEXT NOT NULL,
  creator TEXT NOT NULL,
  description TEXT NOT NULL,
  date TEXT NOT NULL,
  time TEXT NOT NULL,
  address TEXT NOT NULL,
  background_image_url TEXT NOT NULL,
  map_image_url TEXT NOT NULL,
  target_date TIMESTAMP WITH TIME ZONE NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Enable Row Level Security
ALTER TABLE public.events ENABLE ROW LEVEL SECURITY;

-- Create policy to allow everyone to view events
CREATE POLICY "Events are viewable by everyone" 
ON public.events 
FOR SELECT 
USING (true);

-- Create policy to allow authenticated users to insert events
CREATE POLICY "Authenticated users can insert events" 
ON public.events 
FOR INSERT 
TO authenticated
WITH CHECK (true);

-- Create policy to allow authenticated users to update events
CREATE POLICY "Authenticated users can update events" 
ON public.events 
FOR UPDATE 
TO authenticated
USING (true);

-- Create policy to allow authenticated users to delete events
CREATE POLICY "Authenticated users can delete events" 
ON public.events 
FOR DELETE 
TO authenticated
USING (true);

-- Create function to update timestamps
CREATE OR REPLACE FUNCTION public.update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SET search_path = public;

-- Create trigger for automatic timestamp updates
CREATE TRIGGER update_events_updated_at
BEFORE UPDATE ON public.events
FOR EACH ROW
EXECUTE FUNCTION public.update_updated_at_column();

-- Insert sample event data
INSERT INTO public.events (
  title,
  creator,
  description,
  date,
  time,
  address,
  background_image_url,
  map_image_url,
  target_date
) VALUES (
  'Cocktails with a Side of Sounds',
  'EBBA STOPPELBURG',
  'Experience the perfect blend of lakeside serenity, culture, and local charm. Explore stunning waterfronts, discover top wineries and galleries, and savour local dining—your ultimate destination for relaxation, discovery, and adventure.',
  'THURSDAY, OCTOBER 30',
  '16:30 - 18:30 CET',
  'ADDRESS GOES HERE',
  'https://images.unsplash.com/photo-1514525253161-7a46d19cd819?ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D&auto=format&fit=crop&w=1974&q=80',
  'https://api.builder.io/api/v1/image/assets/TEMP/332f98a4dad5cb2efedd96ff4032a25b1c4d8e3a?width=910',
  now() + interval '132 days 12 hours 51 minutes'
);