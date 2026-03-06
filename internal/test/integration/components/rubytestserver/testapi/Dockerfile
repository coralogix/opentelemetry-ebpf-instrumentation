FROM ruby:4.0.1 AS builder

# Set the working directory to /build
WORKDIR /build

ENV BUNDLE_PATH=/usr/local/bundle

# Copy the source code into the image for building
COPY internal/test/integration/components/rubytestserver/testapi .

RUN gem update --system
RUN gem install bundler -v 4.0.7
RUN bundle install
RUN bundle binstubs railties
RUN bundle exec rake db:migrate

FROM ruby:4.0.1-slim

RUN gem update --system

WORKDIR /build

ENV BUNDLE_PATH=/usr/local/bundle

COPY --from=builder /build .
COPY --from=builder /usr/local/bundle /usr/local/bundle

EXPOSE 3040

# Run the node app
CMD [ "bundle", "exec", "rails", "server", "-p", "3040", "-b", "0.0.0.0" ]
