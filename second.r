
new_phishing <- read.csv(file = "file.txt",header = FALSE)
colnames(new_phishing) <- c("having_IP_Address","URL_Length","Shortening_Service","having_At_Symbol","double_slash_redirecting","Prefix_Suffix","having_Sub_Domain","SSLfinal_State","Domain_registration_length","Favicon","port","HTTPS_token","Request_URL","URL_of_Anchor","Links_in_tags","SFH","Submitting_to_email","Abnormal_URL","Redirect","on_mouseover","RightClick","popUpWindow","Iframe","age_of_domain","DNSRecord","web_traffic","Page_Rank","Google_Index","Links_pointing_to_page","Statistical_report","Result")


new_phishing1 <- new_phishing
for(i in 1:31){new_phishing[,i] <- as.integer(new_phishing[,i])}
str(new_phishing)
set.seed(3230)
complete <- rbind(phishing,new_phishing)


complete2 <- complete
his <- preProcess(complete2,method = "knnImpute")
pre <- predict(his,complete2)
complete3 <- pre
complete4 <- complete3


sum16 <- 0
squ16 <- 0
avg16 <- 0
sd16 <- 0
count16 <- 0
for(i in 1:11055){
  if(!is.na(complete2[i,16])){
    count16 <- count16 + 1
    sum16 <- sum16 + complete2[i,16]
  }
}
avg16 <- sum16/count16
for(i in 1:11055){
  if(!is.na(complete2[i,16])){
    ae <- (complete2[i,16] - avg16)^2
    squ16 <- squ16 + ae
  }
}
sd16 <- sqrt(squ16/(count16 - 1))
for(i in 1:11055){
  complete3[i,16] <- (complete3[i,16] * sd16) + avg16
}

sum29 <- 0
squ29 <- 0
avg29 <- 0
sd29 <- 0
count29 <- 0
for(i in 1:11055){
  if(!is.na(complete2[i,29])){
    count29 <- count29 + 1
    sum29 <- sum29 + complete2[i,29]
  }
}
avg29 <- sum29/count29
for(i in 1:11055){
  if(!is.na(complete2[i,29])){
    ae <- (complete2[i,29] - avg29)^2
    squ29 <- squ29 + ae
  }
}
sd29 <- sqrt(squ29/(count29 - 1))
for(i in 1:11055){
  complete3[i,29] <- (complete3[i,29] * sd29) + avg29
}

sum30 <- 0
squ30 <- 0
avg30 <- 0
sd30 <- 0
count30 <- 0
for(i in 1:11055){
  if(!is.na(complete2[i,30])){
    count30 <- count30 + 1
    sum30 <- sum30 + complete2[i,30]
  }
}
avg30 <- sum30/count30
for(i in 1:11055){
  if(!is.na(complete2[i,30])){
    ae <- (complete2[i,30] - avg30)^2
    squ30 <- squ30 + ae
  }
}
sd30 <- sqrt(squ30/(count30 - 1))
for(i in 1:11055){
  complete3[i,30] <- (complete3[i,30] * sd30) + avg30
}

sum31 <- 0
squ31 <- 0
avg31 <- 0
sd31 <- 0
count31 <- 0
for(i in 1:11055){
  if(!is.na(complete2[i,31])){
    count31 <- count31 + 1
    sum31 <- sum31 + complete2[i,31]
  }
}
avg31 <- sum31/count31
for(i in 1:11055){
  if(!is.na(complete2[i,31])){
    ae <- (complete2[i,31] - avg31)^2
    squ31 <- squ31 + ae
  }
}
sd31 <- sqrt(squ31/(count31 - 1))
for(i in 1:11055){
  complete3[i,31] <- (complete3[i,31] * sd31) + avg31
}


for(i in 1:15){
  av <- 0
  sd <- 0
  av <- mean(complete2[,i])
  sd <- sd(complete2[,i])
  for(j in 1:11055){
    complete3[j,i] <- (complete3[j,i] * sd) + av
  }
}

for(i in 17:28){
  av <- 0
  sd <- 0
  av <- mean(complete2[,i])
  sd <- sd(complete2[,i])
  for(j in 1:11055){
    complete3[j,i] <- (complete3[j,i] * sd) + av
  }
}


dim(complete3)
new_phishing2 <- complete3[11055,]
for(i in 1:15){
  new_phishing2[i] <- new_phishing[i];
}
if(new_phishing2[29] >= 1){
  new_phishing2[29] = 1
}else if((new_phishing2[29] >= 0) && (new_phishing2[29] < 1)){
  new_phishing2[29] <- 0
}else{
  new_phishing2[29] <- -1
}
if(new_phishing2[16] >= 1){
  new_phishing2[16] = 1
}else if((new_phishing2[16] >= 0) && (new_phishing2[16] < 1)){
  new_phishing2[16] <- 0
}else{
  new_phishing2[16] <- -1
}

if(new_phishing2[30] >= 0){
  new_phishing2[30] <- 1
}else{
  new_phishing2[30] <- -1
}

if(new_phishing2[31] >= 0){
  new_phishing2[31] <- 1
}else{
  new_phishing2[31] <- -1
}


new_phishing2$new1 <- -(0.7044257*new_phishing2$double_slash_redirecting) - (0.7097778*new_phishing2$Shortening_Service)
new_phishing2$new2 <- (0.7553941*new_phishing2$Submitting_to_email) + (0.6552708*new_phishing2$port)
new_phishing2$new3 <- -(0.7134187*new_phishing2$popUpWindow) - (0.7007380*new_phishing2$Favicon)

new_phishing2 <- new_phishing2[,-c(3,5,10,11,17,22)]
new_phishing2[4] <- -1
new_phishing2[14] <- 0
new_phishing2[22] <- 1

for(i in 1:25){new_phishing2[,i] <- as.factor(new_phishing2[,i])}


newp <- predict(fit13,newdata = new_phishing2)


write.table(newp,"predictionresult.txt")




