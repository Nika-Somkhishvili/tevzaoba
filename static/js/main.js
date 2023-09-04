webhook_url = "https://eospcyrbrulc7gm.m.pipedream.net";

// const button = document.getElementById("myButton");

// button.addEventListener("click", function () {
//   sendToWebhook();
// });

var socket = io();

socket.on("connect", function () {
  console.log("Connected to the server");
});

socket.on("disconnect", function () {
  console.log("Disconnected from the server");
});

socket.on("data", function (item) {
  addItem(item);
});

function addItem(item) {
  // Create the outer div element
  const item_div = document.createElement("div");
  item_div.className = "item";

  // Create the score paragraph element
  const scoreParagraph = document.createElement("p");
  scoreParagraph.className = "score";
  scoreParagraph.textContent = item.score;

  // Create the domain paragraph element
  const domainParagraph = document.createElement("p");
  domainParagraph.className = "domain";
  domainParagraph.textContent = item.domain;

  // Create the action div element
  const actionDiv = document.createElement("div");
  actionDiv.className = "action";

  // Create the Send button
  const sendButton = document.createElement("button");
  sendButton.className = "send-btn";
  sendButton.textContent = "Send";
  sendButton.addEventListener("click", sendToWebhook); // Assuming sendToWebhook is your function

  // Create the Dismiss button
  const dismissButton = document.createElement("button");
  dismissButton.className = "dismiss-btn";
  dismissButton.textContent = "Dismiss";

  // Append the score and domain paragraphs to the item_div
  item_div.appendChild(scoreParagraph);
  item_div.appendChild(domainParagraph);

  // Append the Send and Dismiss buttons to the actionDiv
  actionDiv.appendChild(sendButton);
  actionDiv.appendChild(dismissButton);

  // Append the actionDiv to the item_div
  item_div.appendChild(actionDiv);

  // Get the parent div with the class "items" and append the item_div to it
  const items_div = document.querySelector(".items");
  items_div.appendChild(item_div);
}

function sendToWebhook() {
  console.log("sending post request");
  fetch(webhook_url, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ name: "nika from javascript" }),
  }).then((response) => {
    console.log("Status Code: " + response.status);
  });
}
